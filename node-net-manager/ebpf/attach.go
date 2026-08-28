package ebpf

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// tcAttachment is a single TC filter this Manager installed, kept around so
// it can be torn down again by DetachEgress/DetachDecap/Close.
type tcAttachment struct {
	filter *netlink.BpfFilter
}

func (a *tcAttachment) detach() error {
	if a == nil || a.filter == nil {
		return nil
	}
	return netlink.FilterDel(a.filter)
}

// ensureClsact makes sure the clsact qdisc is present on ifindex. clsact
// provides the ingress/egress hook points TC filters attach to; adding it
// twice is a no-op we treat as success (AttachEgress runs once per veth, and
// multiple veths never share an ifindex, but a restart after a crash could
// find it already there).
func ensureClsact(ifindex int) error {
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifindex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("adding clsact qdisc on ifindex %d: %w", ifindex, err)
	}
	return nil
}

// attachFilter installs prog as a direct-action TC filter at the given
// parent (HANDLE_MIN_INGRESS for both hooks in this design - see the plan's
// "Hooks" table). cilium/ebpf's own link.AttachTCX needs kernel 6.6+, far
// above the 5.4 floor here, so this goes through netlink's classic clsact
// path instead (matches the plan's "Go-side libraries" section).
func attachFilter(ifindex int, parent uint32, prog *ebpf.Program, name string) (*tcAttachment, error) {
	if err := ensureClsact(ifindex); err != nil {
		return nil, err
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		return nil, fmt.Errorf("attaching %s to ifindex %d: %w", name, ifindex, err)
	}
	return &tcAttachment{filter: filter}, nil
}

// AttachEgress installs tc_egress at TC ingress of a host-side veth
// (env.Environment.createVethsPairAndAttachToBridge's veth1). Container
// egress traffic reaches this hook before the bridge, before host routing,
// and before the TUN - all three are bypassed on a fast-path hit. Attaching
// the same ifindex twice is a no-op.
func (m *Manager) AttachEgress(vethIfindex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.egressLinks[vethIfindex]; exists {
		return nil
	}
	a, err := attachFilter(vethIfindex, netlink.HANDLE_MIN_INGRESS, m.objs.TcEgress, "oakestra_tc_egress")
	if err != nil {
		return err
	}
	m.egressLinks[vethIfindex] = a
	return nil
}

// DetachEgress removes the tc_egress hook from a host-side veth, e.g. right
// before it is deleted in DetachContainer. A no-op if nothing was attached.
func (m *Manager) DetachEgress(vethIfindex int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	a, exists := m.egressLinks[vethIfindex]
	if !exists {
		return nil
	}
	delete(m.egressLinks, vethIfindex)
	return a.detach()
}

// AttachDecap installs tc_decap at TC ingress of the node's internet-facing
// NIC (env.Configuration.ConnectedInternetInterface). Idempotent.
func (m *Manager) AttachDecap() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.decapHandle != nil {
		return nil
	}
	a, err := attachFilter(m.nicIfindex, netlink.HANDLE_MIN_INGRESS, m.objs.TcDecap, "oakestra_tc_decap")
	if err != nil {
		return err
	}
	m.decapHandle = a
	return nil
}

// DetachDecap removes the tc_decap hook from the NIC.
func (m *Manager) DetachDecap() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.decapHandle == nil {
		return nil
	}
	err := m.decapHandle.detach()
	m.decapHandle = nil
	return err
}
