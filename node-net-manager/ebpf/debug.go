package ebpf

import (
	"net"
	"strconv"
)

// FlowStats is a point-in-time snapshot used by the e2e harness (see the
// plan's verification step 4: "confirm flow affinity holds and distribution
// is not degenerate") and by manual debugging in place of `bpftool map
// dump`, which is not scriptable from Go.
type FlowStats struct {
	Backend  net.IP
	NodeIP   net.IP
	NodePort int
}

// DumpFlows lists every active flow_ct entry. It is O(map size) and meant
// for tests/debugging, not the hot path.
func (m *Manager) DumpFlows() (map[string]FlowStats, error) {
	out := make(map[string]FlowStats)
	var key bpfFlowKey
	var val bpfFlowCtVal
	it := m.objs.FlowCt.Iterate()
	for it.Next(&key, &val) {
		src := unmapAddr(key.Saddr)
		dst := unmapAddr(key.Daddr)
		flowID := src.String() + ":" + portString(key.Sport) + "->" + dst.String() + ":" + portString(key.Dport)
		out[flowID] = FlowStats{
			Backend:  unmapAddr(val.BackendNsip),
			NodeIP:   unmapAddr(val.NodeIp),
			NodePort: int(val.NodePort),
		}
	}
	return out, it.Err()
}

func portString(networkOrderPort uint16) string {
	// Ports in flow_key are stored in network byte order (copied straight
	// out of the TCP/UDP header), so byte-swap before printing.
	swapped := (networkOrderPort >> 8) | (networkOrderPort << 8)
	return strconv.Itoa(int(swapped))
}
