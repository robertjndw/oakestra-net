package proxy

import (
	"NetManager/proxy/iputils"
	"NetManager/resolver"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

// These benchmarks exercise the packet-translation hot path exactly as the
// datapath goroutines call it. b.ReportAllocs() is the acceptance check for
// the zero-copy rewrite: this should show 0 allocs/op.

func benchmarkOutgoing(b *testing.B, wire []byte) {
	dp := getFakeDatapath()
	buf := make([]byte, len(wire))

	// warm the flow cache so the benchmark measures the steady state rather
	// than route selection
	copy(buf, wire)
	pkt, _ := iputils.Parse(buf)
	if _, _, _, ok := dp.outgoingProxy(&pkt); !ok {
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
		if _, _, _, proxied := dp.outgoingProxy(&pkt); !proxied {
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
	dp := getFakeDatapath()
	dp.proxycache.Add(ConversionEntry{
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
		if !dp.ingoingProxy(&pkt) {
			b.Fatal("expected packet to match reverse cache entry")
		}
	}
}

// BenchmarkHandleOutgoingLoopback measures the complete outgoing path -
// parse, translate, and an actual UDP write to another node - rather than the
// translation alone.
func BenchmarkHandleOutgoingLoopback(b *testing.B) {
	tunnel, listener := loopbackTunnel(b)

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

	// Warm the flow cache and dial the socket on a copy: Handle rewrites the
	// packet in place, and reusing the rewritten one would leave the
	// benchmark measuring a destination that is no longer proxied at all.
	copy(buf, wire)
	tunnel.Emit(tunnel.dp.Handle(Outgoing, buf))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(buf, wire)
		tunnel.Emit(tunnel.dp.Handle(Outgoing, buf))
	}
}

// BenchmarkFlowCacheParallel exercises the striped locks with both datapath
// directions running at once, which is what the replay goroutines and the
// eviction sweep made possible.
func BenchmarkFlowCacheParallel(b *testing.B) {
	dp := getFakeDatapath()
	outgoing := buildTestPacketV4(b, clientNsIP, serverVIP, 40000, 443)
	dp.Handle(Outgoing, append([]byte(nil), outgoing...))
	incoming := buildTestPacketV4(b, serverInstIP, clientNsIP, 443, 40000)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		out := make([]byte, len(outgoing))
		in := make([]byte, len(incoming))
		for pb.Next() {
			copy(out, outgoing)
			pkt, _ := iputils.Parse(out)
			dp.outgoingProxy(&pkt)

			copy(in, incoming)
			reply, _ := iputils.Parse(in)
			dp.ingoingProxy(&reply)
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
			dp := fakeDatapathOn(nodeAIP, newFakeEnv(replicatedFixture(b, replicas)...))

			wire := buildTestPacketV4(b, clientNsIP, serverVIP, 666, 80)
			buf := make([]byte, len(wire))
			copy(buf, wire)
			pkt, _ := iputils.Parse(buf)
			if _, _, _, ok := dp.outgoingProxy(&pkt); !ok {
				b.Fatal("expected packet to be proxied")
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				copy(buf, wire)
				pkt, _ := iputils.Parse(buf)
				if _, _, _, ok := dp.outgoingProxy(&pkt); !ok {
					b.Fatal("expected packet to be proxied")
				}
			}
		})
	}
}

// BenchmarkOutgoingProxyRegeneration shows the cost of the other cache hit -
// one whose route was chosen under a generation the table has since moved
// past, forcing exactly one revalidation scan against the service's replicas
// before the route can be reused. This is where ProxyCache.Route's single
// lock/scan pays off over the old three-call protocol (RetrieveByServiceIP,
// IsRouteStillValid, MarkRouteCurrent), which took the lock three times and
// scanned the bucket three times for the same outcome.
func BenchmarkOutgoingProxyRegeneration(b *testing.B) {
	for _, replicas := range []int{1, 10, 100, 1000} {
		b.Run(fmt.Sprintf("replicas=%d", replicas), func(b *testing.B) {
			dp := fakeDatapathOn(nodeAIP, newFakeEnv(replicatedFixture(b, replicas)...))

			wire := buildTestPacketV4(b, clientNsIP, serverVIP, 666, 80)
			buf := make([]byte, len(wire))
			copy(buf, wire)
			pkt, _ := iputils.Parse(buf)
			if _, _, _, ok := dp.outgoingProxy(&pkt); !ok {
				b.Fatal("expected packet to be proxied")
			}

			lookup := dp.environment.GetTableEntryByServiceIP(mustAddr(serverVIP))
			key := FlowKey{
				Protocol:      iputils.ProtoTCP,
				SrcIP:         mustAddr(clientNsIP),
				SrcInstanceIP: mustAddr(clientInstIP),
				DstServiceIP:  mustAddr(serverVIP),
				SrcPort:       666,
				DstPort:       80,
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// A generation Route hasn't tagged the entry with yet forces
				// the revalidation scan on this call; Route then retags the
				// entry with it, so the next iteration has to hand it a
				// fresh one too, keeping every call on the regeneration path
				// instead of just the first.
				stale := resolver.ServiceLookup{Entries: lookup.Entries, Generation: lookup.Generation + 1 + uint64(i)}
				if _, ok := dp.proxycache.Route(key, stale); !ok {
					b.Fatal("expected the route to revalidate")
				}
			}
		})
	}
}

// benchNoopBatchWriter counts WriteBatch calls without copying the packets
// it's handed, unlike fakeBatchWriter - that copy exists for the correctness
// tests' assertions, and would otherwise dominate an allocation count that's
// supposed to isolate the batching machinery itself, not the test double.
type benchNoopBatchWriter struct{ calls int }

func (w *benchNoopBatchWriter) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	w.calls++
	return len(ms), nil
}

// BenchmarkOutgoingBatchGrouping isolates the cost this whole change is for:
// grouping one TunDevice read's ActionForward packets by destination and
// issuing one WriteBatch per group, with real sends stubbed out so the number
// measured is the batching machinery itself, not socket I/O. b.ReportAllocs()
// is the check that grouping N packets across a steady set of destinations
// never allocates once the batch's buffers, groups and message scratch have
// grown to fit (see outgoingBatch).
func BenchmarkOutgoingBatchGrouping(b *testing.B) {
	sock := &fakeTunnelSocket{}
	tunDev := &fakeTunDevice{batchSize: 32}
	tunnel := batchTestTunnel(sock, tunDev)

	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeBIP), uint16(tunnelPort))] = fakeConn(b, &benchNoopBatchWriter{})
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeCIP), uint16(tunnelPort))] = fakeConn(b, &benchNoopBatchWriter{})

	var packets [][]byte
	for i := 0; i < 16; i++ {
		packets = append(packets, buildTestPacketV4(b, clientNsIP, serverVIP, 40000+i, 443))
	}
	for i := 0; i < 16; i++ {
		packets = append(packets, buildTestPacketV4(b, clientNsIP, otherVIP, 50000+i, 443))
	}

	batch := newOutgoingBatch(tunDev.BatchSize())

	// readQueue is refilled every iteration below by reassigning this same
	// backing array, never by re-appending: fakeTunDevice.ReadBatch drains
	// its own copy of the slice header by reslicing off the front
	// (f.readQueue = f.readQueue[1:]), which never touches this one, so
	// resetting tunDev.readQueue = readQueue costs nothing once readQueue
	// itself is built. Rebuilding it with append every iteration would
	// measure that rebuild, not the grouping machinery under test.
	readQueue := append([][]byte(nil), packets...)

	// Warm the batch's grouping map, per-destination buffer slices and
	// message scratch, so the measured loop is the steady state - see
	// outgoingBatch's own comments on why none of that grows again afterwards.
	tunDev.readQueue = readQueue
	if err := tunnel.runOutgoingBatch(batch); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tunDev.readQueue = readQueue
		if err := tunnel.runOutgoingBatch(batch); err != nil {
			b.Fatal(err)
		}
	}
}
