package proxy

import (
	"NetManager/proxy/iputils"
	"net/netip"
	"testing"
)

// These benchmarks exercise the packet-translation hot path exactly as the
// datapath goroutines call it. b.ReportAllocs() is the acceptance check for
// the zero-copy rewrite: this should show 0 allocs/op.

func BenchmarkOutgoingProxyV4(b *testing.B) {
	proxy := getFakeTunnel()
	wire := buildTestPacketV4(b, "10.19.1.1", "10.30.255.255", 666, 80)
	buf := make([]byte, len(wire))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		pkt, ok := iputils.Parse(buf)
		if !ok || !pkt.HasTransport() {
			b.Fatal("parse failed")
		}
		if _, _, proxied := proxy.outgoingProxy(&pkt); !proxied {
			b.Fatal("expected packet to be proxied")
		}
	}
}

func BenchmarkOutgoingProxyV6(b *testing.B) {
	proxy := getFakeTunnel()
	wire := buildTestPacketV6(b, "fc00::1", "fdff:2000::ff", 666, 80)
	buf := make([]byte, len(wire))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		pkt, ok := iputils.Parse(buf)
		if !ok || !pkt.HasTransport() {
			b.Fatal("parse failed")
		}
		if _, _, proxied := proxy.outgoingProxy(&pkt); !proxied {
			b.Fatal("expected packet to be proxied")
		}
	}
}

func BenchmarkIngoingProxyV4(b *testing.B) {
	proxy := getFakeTunnel()
	proxy.proxycache.Add(ConversionEntry{
		srcip:         netip.MustParseAddr("10.19.1.15"),
		dstip:         netip.MustParseAddr("10.19.2.1"),
		dstServiceIp:  netip.MustParseAddr("10.30.255.255"),
		srcInstanceIp: netip.MustParseAddr("10.30.0.50"),
		srcport:       777,
		dstport:       666,
	})
	wire := buildTestPacketV4(b, "10.30.0.5", "10.19.1.15", 666, 777)
	buf := make([]byte, len(wire))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		pkt, ok := iputils.Parse(buf)
		if !ok || !pkt.HasTransport() {
			b.Fatal("parse failed")
		}
		if !proxy.ingoingProxy(&pkt) {
			b.Fatal("expected packet to match reverse cache entry")
		}
	}
}
