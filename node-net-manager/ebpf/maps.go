package ebpf

import (
	"NetManager/TableEntryCache"
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// maxBackends must match MAX_BACKENDS in oakestra.c.
const maxBackends = 16

// BackendSource is the minimum a caller needs to provide per candidate
// backend behind a VIP; env.Environment builds these from
// TableEntryCache.TableEntry the same way ProxyTunnel.outgoingProxy does
// today, minus the random pick (that becomes an in-kernel hash - see
// oakestra.c's select_backend).
type BackendSource struct {
	Nsip       net.IP
	NodeIP     net.IP
	NodePort   int
	OnThisNode bool
}

// SyncServiceBackends mirrors one VIP's full candidate set into the
// service_backends map, replacing whatever was there. policy must be one of
// TableEntryCache.InstanceNumber / .RoundRobin / .Closest - it decides
// which selection algorithm oakestra.c's select_backend uses. Backends
// beyond maxBackends are dropped; the plan treats this as a fixed prototype
// limit, not something worth a dynamically sized map value.
func (m *Manager) SyncServiceBackends(vip net.IP, policy TableEntryCache.ServiceIpType, backends []BackendSource) error {
	vipAddr, ok := mapAddr(vip)
	if !ok {
		return nil // IPv6 VIP: not on the fast path until M3
	}
	if len(backends) > maxBackends {
		backends = backends[:maxBackends]
	}

	var val bpfServiceBackendsVal
	val.Policy = uint8(policy)
	val.Count = uint32(len(backends))
	for i, b := range backends {
		nsip, ok := mapAddr(b.Nsip)
		if !ok {
			continue
		}
		nodeIP, ok := mapAddr(b.NodeIP)
		if !ok {
			continue
		}
		val.Backends[i] = bpfBackend{
			Nsip:       nsip,
			NodeIp:     nodeIP,
			NodePort:   uint16(b.NodePort),
			OnThisNode: boolToU8(b.OnThisNode),
		}
	}

	if err := m.objs.ServiceBackends.Put(&vipAddr, &val); err != nil {
		return fmt.Errorf("ebpf: syncing service_backends for %s: %w", vip, err)
	}
	return nil
}

// RemoveServiceBackends deletes a VIP's entry, e.g. once its last instance
// is undeployed (env.Environment.RemoveServiceEntries). Removing an absent
// entry is not an error - both directions of that race are harmless: the
// fast path just perf-events a miss and falls through to ProxyTUN.
func (m *Manager) RemoveServiceBackends(vip net.IP) error {
	vipAddr, ok := mapAddr(vip)
	if !ok {
		return nil
	}
	if err := m.objs.ServiceBackends.Delete(&vipAddr); err != nil && !isMapENOENT(err) {
		return fmt.Errorf("ebpf: removing service_backends for %s: %w", vip, err)
	}
	return nil
}

// SetLocalInstance records that a container's namespace IP is reachable on
// this node through the given host-side/peer veth ifindex pair (see
// env.ContainerNetDeployment.DeployNetwork). This is what lets tc_egress
// and tc_decap skip encapsulation entirely for node-local traffic.
func (m *Manager) SetLocalInstance(nsip net.IP, vethIfindex, peerIfindex int) error {
	nsipAddr, ok := mapAddr(nsip)
	if !ok {
		return nil
	}
	val := bpfLocalInstanceVal{VethIfindex: uint32(vethIfindex), PeerIfindex: uint32(peerIfindex)}
	if err := m.objs.LocalInstances.Put(&nsipAddr, &val); err != nil {
		return fmt.Errorf("ebpf: setting local_instances for %s: %w", nsip, err)
	}
	return nil
}

// ClearLocalInstance removes a container's local_instances entry, e.g. from
// env.Environment.DetachContainer.
func (m *Manager) ClearLocalInstance(nsip net.IP) error {
	nsipAddr, ok := mapAddr(nsip)
	if !ok {
		return nil
	}
	if err := m.objs.LocalInstances.Delete(&nsipAddr); err != nil && !isMapENOENT(err) {
		return fmt.Errorf("ebpf: clearing local_instances for %s: %w", nsip, err)
	}
	return nil
}

// SetInstanceIP mirrors convertToInstanceIp (ProxyTunnel.go): a container's
// namespace IP maps to its own InstanceNumber ServiceIP, the address
// tc_egress rewrites the packet's source to on the way out.
func (m *Manager) SetInstanceIP(containerNsip, instanceServiceIP net.IP) error {
	nsipAddr, ok := mapAddr(containerNsip)
	if !ok {
		return nil
	}
	sipAddr, ok := mapAddr(instanceServiceIP)
	if !ok {
		return nil
	}
	if err := m.objs.InstanceIp.Put(&nsipAddr, &sipAddr); err != nil {
		return fmt.Errorf("ebpf: setting instance_ip for %s: %w", containerNsip, err)
	}
	return nil
}

// ClearInstanceIP removes a container's instance_ip entry.
func (m *Manager) ClearInstanceIP(containerNsip net.IP) error {
	nsipAddr, ok := mapAddr(containerNsip)
	if !ok {
		return nil
	}
	if err := m.objs.InstanceIp.Delete(&nsipAddr); err != nil && !isMapENOENT(err) {
		return fmt.Errorf("ebpf: clearing instance_ip for %s: %w", containerNsip, err)
	}
	return nil
}

func isMapENOENT(err error) bool {
	return errors.Is(err, ebpf.ErrKeyNotExist)
}
