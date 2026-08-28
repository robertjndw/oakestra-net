package ebpf

import "net"

// mapAddr converts a net.IP into the v4-mapped 16-byte layout the BPF maps
// use (see oakestra.c's struct ip_addr). Only IPv4 is supported through M2;
// a v6 address is rejected so callers fall back to the ProxyTUN path exactly
// like the BPF programs do on anything they don't understand.
func mapAddr(ip net.IP) (bpfIpAddr, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return bpfIpAddr{}, false
	}
	var out bpfIpAddr
	out.Addr[10] = 0xff
	out.Addr[11] = 0xff
	copy(out.Addr[12:16], v4)
	return out, true
}

func unmapAddr(a bpfIpAddr) net.IP {
	return net.IPv4(a.Addr[12], a.Addr[13], a.Addr[14], a.Addr[15])
}

// IsIPv4Supported reports whether ip can be represented on the fast path.
// The v4-mapped map layout already carries room for real IPv6 (M3 work);
// until then anything that isn't a plain IPv4 address must stay on ProxyTUN.
func IsIPv4Supported(ip net.IP) bool {
	return ip.To4() != nil
}
