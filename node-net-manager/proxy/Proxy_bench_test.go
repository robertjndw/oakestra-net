package proxy

import (
	"NetManager/proxy/iputils"
	"encoding/hex"
	"net"
	"testing"
)

// M0 baseline: quantifies the userspace decode/select/serialize cost this
// package's TC fast path (see ../ebpf) is meant to remove entirely for the
// packets it can handle. Compare against the eBPF path with:
//
//	go test -bench=. ./proxy/...

// benchOutgoingFixture builds a packet plus a reset closure. outgoingProxy's
// SerializePacket call rewrites the packet's src/dst IPs in place
// (v4Packet.go) - for the forward direction that moves the destination out
// of the proxied subnetwork, so every iteration must restore the original
// 5-tuple before the next call rather than reusing the mutated packet.
func benchOutgoingFixture(srcIP, dstIP string, srcPort, dstPort int) (iputils.NetworkLayerPacket, iputils.TransportLayerProtocol, func()) {
	_, ip, tcp := getFakePacket(srcIP, dstIP, srcPort, dstPort)
	ipv4 := ip.(*iputils.IPv4Packet)
	origSrc, origDst := net.ParseIP(srcIP), net.ParseIP(dstIP)
	reset := func() {
		ipv4.SrcIP = origSrc
		ipv4.DstIP = origDst
	}
	return ip, tcp, reset
}

// BenchmarkOutgoingProxy_CacheHit is the steady-state cost once a flow's
// proxycache entry already exists: no backend selection, straight through
// to ip.SerializePacket's decode/serialize/checksum work.
func BenchmarkOutgoingProxy_CacheHit(b *testing.B) {
	proxy := getFakeTunnel()
	ip, tcp, reset := benchOutgoingFixture("10.19.1.1", "10.30.255.255", 666, 80)

	// warm the cache once, outside the timed loop
	if proxy.outgoingProxy(ip, tcp) == nil {
		b.Fatal("expected a proxied packet")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reset()
		if proxy.outgoingProxy(ip, tcp) == nil {
			b.Fatal("expected a proxied packet")
		}
	}
}

// BenchmarkOutgoingProxy_CacheMiss forces a fresh proxycache entry (and
// therefore backend selection via randseed.Intn) on every iteration by
// varying the source port, modeling the worst case: a burst of new flows.
func BenchmarkOutgoingProxy_CacheMiss(b *testing.B) {
	proxy := getFakeTunnel()

	type fixture struct {
		ip    iputils.NetworkLayerPacket
		tcp   iputils.TransportLayerProtocol
		reset func()
	}
	const pool = 65536
	fixtures := make([]fixture, pool)
	for i := range fixtures {
		ip, tcp, reset := benchOutgoingFixture("10.19.1.1", "10.30.255.255", i, 80)
		fixtures[i] = fixture{ip: ip, tcp: tcp, reset: reset}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f := fixtures[i%pool]
		f.reset()
		if proxy.outgoingProxy(f.ip, f.tcp) == nil {
			b.Fatal("expected a proxied packet")
		}
	}
}

// BenchmarkIngoingProxy is the reverse-direction cost: proxycache lookup by
// instance IP plus a full SerializePacket.
func BenchmarkIngoingProxy(b *testing.B) {
	proxy := getFakeTunnel()
	_, ip, tcp := getFakePacket("10.30.0.5", "10.19.1.15", 666, 777)

	proxy.proxycache.Add(ConversionEntry{
		srcip:         net.ParseIP("10.19.1.15"),
		dstip:         net.ParseIP("10.19.2.1"),
		dstServiceIp:  net.ParseIP("10.30.255.255"),
		srcInstanceIp: net.ParseIP("10.30.0.50"),
		srcport:       777,
		dstport:       666,
	})

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if proxy.ingoingProxy(ip, tcp) == nil {
			b.Fatal("expected a proxied packet")
		}
	}
}

// BenchmarkDecodePacket isolates the gopacket decode step alone (the "full
// eager gopacket decode" the plan calls out in ProxyTunnel.go's hot path),
// using the same hex fixtures as Proxy_test.go.
func BenchmarkDecodePacket(b *testing.B) {
	msg, err := hex.DecodeString(ipv4Packet)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if ip, _ := decodePacket(msg); ip == nil {
			b.Fatal("expected a decoded packet")
		}
	}
}

// BenchmarkPacketToByte isolates one of the three serialization passes
// ProxyTunnel.go performs per packet (see v4Packet.go's serializeIPHeader,
// which itself does two more before this one is even called).
func BenchmarkPacketToByte(b *testing.B) {
	_, ipLayer, tcp := getFakePacket("10.19.1.1", "10.30.255.255", 666, 80)
	packet := ipLayer.SerializePacket(ipLayer.GetDestIP(), ipLayer.GetSrcIP(), tcp)
	if packet == nil {
		b.Fatal("expected a serialized packet")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = packetToByte(packet)
	}
}
