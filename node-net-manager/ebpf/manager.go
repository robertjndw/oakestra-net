// Package ebpf loads and manages the TC fast path from oakestra.c: it is an
// accelerator for proxy.GoProxyTunnel, never a replacement. Every program it
// attaches falls through to TC_ACT_OK - and therefore back into the
// existing ProxyTUN datapath - on anything it does not recognize, so a
// Manager that fails to load, or that a caller never creates, changes
// nothing about existing behavior.
package ebpf

import (
	"NetManager/logger"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// KernelFloorMajor.KernelFloorMinor is the minimum kernel this fast path
// supports (see the plan's "Portability" section: ARM edge boards with no
// CO-RE toolchain guaranteed present).
const (
	KernelFloorMajor = 5
	KernelFloorMinor = 4
)

// ErrKernelTooOld is returned by Load when the running kernel is below the
// support floor; callers should fall back to pure ProxyTUN.
var ErrKernelTooOld = errors.New("ebpf: kernel below the 5.4 support floor")

// Manager owns the loaded BPF programs, their maps, and their TC
// attachments.
type Manager struct {
	objs bpfObjects

	mu          sync.Mutex
	nicIfindex  int
	decapHandle *tcAttachment
	egressLinks map[int]*tcAttachment // keyed by host-side veth ifindex

	haveRedirectPeer bool

	reader *perf.Reader

	// OnVIPMiss is invoked, on its own goroutine per event, whenever
	// tc_egress sees a service VIP with no service_backends entry. The
	// packet has already gone down the existing TUN path for that one
	// packet (see the plan's "Slow path" section); the callback is expected
	// to run the existing table-query flow and then call
	// SyncServiceBackends so later packets take the fast path.
	OnVIPMiss func(vip net.IP)
}

// HaveRedirectPeer reports whether the kernel supports bpf_redirect_peer,
// as determined once at Load time.
func (m *Manager) HaveRedirectPeer() bool {
	return m.haveRedirectPeer
}

// Load probes the running kernel, loads the BPF objects, and returns a
// Manager with no hooks attached yet - call AttachEgress per veth and
// AttachDecap once for the NIC. nicIfindex/nodeIP/tunnelPort populate the
// `cfg` map that both TC programs read on every packet.
func Load(nicIfindex int, nodeIP net.IP, tunnelPort int) (*Manager, error) {
	major, minor, err := kernelVersion()
	if err != nil {
		return nil, fmt.Errorf("ebpf: probing kernel version: %w", err)
	}
	if major < KernelFloorMajor || (major == KernelFloorMajor && minor < KernelFloorMinor) {
		return nil, ErrKernelTooOld
	}

	nodeAddr, ok := mapAddr(nodeIP)
	if !ok {
		return nil, fmt.Errorf("ebpf: node IP %s is not IPv4", nodeIP)
	}

	// Locked-memory rlimit: pre-5.11 kernels charge BPF map memory against
	// RLIMIT_MEMLOCK, which is 64KB by default on most distros - nowhere
	// near enough for the 65536-entry flow_ct/flow_ct_rev LRU maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.ErrorLogger().Println("ebpf: RemoveMemlock (continuing anyway):", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: loading BPF objects: %w", err)
	}

	haveRedirectPeer := probeRedirectPeer()

	cfgVal := bpfCfgVal{
		NicIfindex:       uint32(nicIfindex),
		NodeIp:           nodeAddr,
		TunnelPort:       uint16(tunnelPort),
		HaveRedirectPeer: boolToU8(haveRedirectPeer),
	}
	var cfgKey uint32
	if err := objs.Cfg.Put(&cfgKey, &cfgVal); err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("ebpf: writing cfg map: %w", err)
	}

	reader, err := perf.NewReader(objs.Slowpath, os.Getpagesize())
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("ebpf: opening slowpath perf reader: %w", err)
	}

	m := &Manager{
		objs:             objs,
		nicIfindex:       nicIfindex,
		egressLinks:      make(map[int]*tcAttachment),
		haveRedirectPeer: haveRedirectPeer,
		reader:           reader,
	}
	go m.drainSlowpath()

	logger.InfoLogger().Printf(
		"ebpf: fast path loaded (kernel %d.%d, redirect_peer=%v, nic ifindex=%d)",
		major, minor, haveRedirectPeer, nicIfindex,
	)
	return m, nil
}

// Close detaches every TC hook this Manager installed, stops the slowpath
// drainer, and unloads the BPF objects. Safe to call on a Manager whose
// Load partially failed.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.reader != nil {
		_ = m.reader.Close()
	}
	if m.decapHandle != nil {
		_ = m.decapHandle.detach()
		m.decapHandle = nil
	}
	for ifindex, a := range m.egressLinks {
		_ = a.detach()
		delete(m.egressLinks, ifindex)
	}
	return m.objs.Close()
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
