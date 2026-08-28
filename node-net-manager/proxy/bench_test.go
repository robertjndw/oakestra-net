package proxy

import (
	"NetManager/proxy/iputils"
	"fmt"
	"testing"
	"time"
)

// These benchmarks exercise the packet-translation hot path exactly as the
// datapath goroutines call it. b.ReportAllocs() is the acceptance check for
// the zero-copy rewrite: this should show 0 allocs/op.

func benchmarkOutgoing(b *testing.B, wire []byte) {
	proxy := getFakeTunnel()
	buf := make([]byte, len(wire))

	// warm the flow cache so the benchmark measures the steady state rather
	// than route selection
	copy(buf, wire)
	pkt, _ := iputils.Parse(buf)
	if _, _, _, ok := proxy.outgoingProxy(&pkt); !ok {
		b.Fatal("expected packet to be proxied")
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		pkt, ok := iputils.Parse(buf)
		if !ok || !pkt.HasTransport() {
			b.Fatal("parse failed")
		}
		if _, _, _, proxied := proxy.outgoingProxy(&pkt); !proxied {
			b.Fatal("expected packet to be proxied")
		}
	}
}

func BenchmarkOutgoingProxyV4(b *testing.B) {
	benchmarkOutgoing(b, buildTestPacketV4(b, clientNsIP, serverVIP, 666, 80))
}

func BenchmarkOutgoingProxyV6(b *testing.B) {
	benchmarkOutgoing(b, buildTestPacketV6(b, clientNsIPv6, serverVIPv6, 666, 80))
}

func BenchmarkIngoingProxyV4(b *testing.B) {
	proxy := getFakeTunnel()
	proxy.proxycache.Add(ConversionEntry{
		srcip:         mustAddr(clientNsIP),
		dstip:         mustAddr(serverNsIP),
		dstServiceIp:  mustAddr(serverVIP),
		srcInstanceIp: mustAddr(clientInstIP),
		dstInstanceIp: mustAddr(serverInstIP),
		srcport:       666,
		dstport:       80,
		protocol:      iputils.ProtoTCP,
	})
	wire := buildTestPacketV4(b, serverInstIP, clientNsIP, 80, 666)
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

// BenchmarkHandleOutgoingLoopback measures the complete outgoing path -
// parse, translate, and an actual UDP write to another node - rather than the
// translation alone.
func BenchmarkHandleOutgoingLoopback(b *testing.B) {
	proxy, listener := loopbackTunnel(b)

	// Drain the far end so the socket buffer can't fill and skew the writes.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			if _, _, err := listener.ReadFromUDP(buf); err != nil {
				continue
			}
		}
	}()
	b.Cleanup(func() { close(done) })

	wire := buildTestPacketV4(b, clientNsIP, serverVIP, 666, 80)
	buf := make([]byte, len(wire))

	// Warm the flow cache and dial the socket on a copy: handleOutgoing
	// rewrites the packet in place, and reusing the rewritten one would leave
	// the benchmark measuring a destination that is no longer proxied at all.
	copy(buf, wire)
	proxy.handleOutgoing(buf, false)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		proxy.handleOutgoing(buf, false)
	}
}

// BenchmarkFlowCacheParallel exercises the striped locks with both datapath
// directions running at once, which is what the replay goroutines and the
// eviction sweep made possible.
func BenchmarkFlowCacheParallel(b *testing.B) {
	proxy := getFakeTunnel()
	outgoing := buildTestPacketV4(b, clientNsIP, serverVIP, 40000, 443)
	proxy.handleOutgoing(append([]byte(nil), outgoing...), false)
	incoming := buildTestPacketV4(b, serverInstIP, clientNsIP, 443, 40000)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		out := make([]byte, len(outgoing))
		in := make([]byte, len(incoming))
		for pb.Next() {
			copy(out, outgoing)
			pkt, _ := iputils.Parse(out)
			proxy.outgoingProxy(&pkt)

			copy(in, incoming)
			reply, _ := iputils.Parse(in)
			proxy.ingoingProxy(&reply)
		}
	})
}

// BenchmarkOutgoingProxyReplicas shows the cost of a warm cache hit as the
// service's replica count grows. Revalidating a cached route used to scan
// every replica on every packet; while the table is unchanged that scan is
// skipped entirely.
func BenchmarkOutgoingProxyReplicas(b *testing.B) {
	for _, replicas := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("replicas=%d", replicas), func(b *testing.B) {
			proxy := getFakeTunnel()
			proxy.SetEnvironment(newFakeEnv(replicatedFixture(b, replicas)...))

			wire := buildTestPacketV4(b, clientNsIP, serverVIP, 666, 80)
			buf := make([]byte, len(wire))
			copy(buf, wire)
			pkt, _ := iputils.Parse(buf)
			if _, _, _, ok := proxy.outgoingProxy(&pkt); !ok {
				b.Fatal("expected packet to be proxied")
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(buf, wire)
				pkt, _ := iputils.Parse(buf)
				if _, _, _, ok := proxy.outgoingProxy(&pkt); !ok {
					b.Fatal("expected packet to be proxied")
				}
			}
		})
	}
}
