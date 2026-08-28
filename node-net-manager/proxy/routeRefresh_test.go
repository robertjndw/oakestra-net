package proxy

import (
	"NetManager/proxy/iputils"
	"NetManager/resolver"
	"testing"
	"time"
)

// TestCachedRouteSurvivesUnchangedTable: while the translation table has not
// moved, a cached flow keeps its route and is tagged with the current
// generation, which is what lets the packet path skip rescanning every replica
// of the service on each hit.
func TestCachedRouteSurvivesUnchangedTable(t *testing.T) {
	dp := getFakeDatapath()
	environment := dp.environment.(*FakeEnv)

	if node := translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Fatalf("forwarded to %s; want %s", node, nodeBIP)
	}

	_, generation := environment.table.SearchByServiceIP(mustAddr(serverVIP))
	if got := routeGenOf(t, dp, iputils.ProtoTCP, clientNsIP, clientInstIP, serverVIP, 40000, 443); got != generation {
		t.Errorf("cached route tagged with generation %d; table is at %d", got, generation)
	}

	if node := translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Errorf("second packet forwarded to %s; want the cached route %s", node, nodeBIP)
	}
}

// TestCachedRouteRevalidatedOnce checks that a route survives one
// revalidation scan after the table's generation moves, and that the next
// call trusts the retagged generation instead of scanning again - the second
// call is handed a lookup whose Entries would fail that scan if it ran.
func TestCachedRouteRevalidatedOnce(t *testing.T) {
	dp := getFakeDatapath()
	environment := dp.environment.(*FakeEnv)

	translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))

	key := FlowKey{
		Protocol:      iputils.ProtoTCP,
		SrcIP:         mustAddr(clientNsIP),
		SrcInstanceIP: mustAddr(clientInstIP),
		DstServiceIP:  mustAddr(serverVIP),
		SrcPort:       40000,
		DstPort:       443,
	}

	// Bump the table generation without changing serverapp's route at all.
	environment.replaceJob(t, fixtureEntries[1].JobName, fixtureEntries[1])
	entries, generation := environment.table.SearchByServiceIP(mustAddr(serverVIP))

	if _, ok := dp.proxycache.Route(key, resolver.ServiceLookup{Entries: entries, Generation: generation}); !ok {
		t.Fatal("a route that is still valid should survive revalidation")
	}
	if got := routeGenOf(t, dp, key.Protocol, clientNsIP, clientInstIP, serverVIP, key.SrcPort, key.DstPort); got != generation {
		t.Fatalf("cached route not retagged after revalidation: generation %d, want %d", got, generation)
	}

	// The generation now matches, so this lookup must be trusted on the tag
	// alone: its empty Entries would fail IsRouteStillValid if it ran.
	if _, ok := dp.proxycache.Route(key, resolver.ServiceLookup{Generation: generation}); !ok {
		t.Error("a cached route was rescanned (and failed) instead of trusting its generation tag")
	}
}

// TestCachedRouteFollowsNodeChange: a refresh can move an instance to another
// node while its namespace IP stays the same. A cached flow that only compared
// namespace IPs would keep tunnelling to the old node forever, because cache
// hits refresh the entry's own idle timer.
func TestCachedRouteFollowsNodeChange(t *testing.T) {
	for _, tc := range []struct {
		name          string
		node          string
		port          int
		wantForwarded string
	}{
		{"node ip changed", nodeCIP, tunnelPort, nodeCIP},
		{"node port changed", nodeBIP, tunnelPort + 1, nodeBIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dp := getFakeDatapath()
			environment := dp.environment.(*FakeEnv)

			translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))

			moved := tableEntry("serverapp", tc.node, serverNsIP, serverNsIPv6,
				serverVIP, serverVIPv6, serverInstIP, serverInstIPv6)
			moved.Nodeport = tc.port
			environment.replaceJob(t, moved.JobName, moved)

			pkt := parseTestPacket(t, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
			node, port, _, ok := dp.outgoingProxy(&pkt)
			if !ok {
				t.Fatal("packet should still have been proxied")
			}
			if node.String() != tc.wantForwarded || port != tc.port {
				t.Errorf("forwarded to %s:%d after the refresh; want %s:%d",
					node, port, tc.wantForwarded, tc.port)
			}
		})
	}
}

// TestCachedRouteDroppedWhenInstanceRemoved: once the only instance is gone
// there is no route to fall back on, so the packet must be dropped rather than
// sent to the stale node.
func TestCachedRouteDroppedWhenInstanceRemoved(t *testing.T) {
	dp := getFakeDatapath()
	environment := dp.environment.(*FakeEnv)

	translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	environment.replaceJob(t, fixtureEntries[1].JobName)

	pkt := parseTestPacket(t, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	if _, _, _, ok := dp.outgoingProxy(&pkt); ok {
		t.Error("a flow to a removed instance was still forwarded")
	}
}

// TestIdleTunnelConnectionsEvicted checks that a tunnel connection unused
// past the idle timeout gets closed, while one still in use survives.
func TestIdleTunnelConnectionsEvicted(t *testing.T) {
	tunnel, _ := loopbackTunnel(t)

	tunnel.Emit(tunnel.dp.Handle(Outgoing, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)))

	tunnel.connectionBufferLock.RLock()
	established := len(tunnel.connectionBuffer)
	tunnel.connectionBufferLock.RUnlock()
	if established != 1 {
		t.Fatalf("%d tunnel connections open; want 1", established)
	}

	// A connection used moments ago is not idle.
	tunnel.evictIdleConnections(time.Hour)
	tunnel.connectionBufferLock.RLock()
	kept := len(tunnel.connectionBuffer)
	tunnel.connectionBufferLock.RUnlock()
	if kept != 1 {
		t.Error("a connection in active use was evicted")
	}

	tunnel.evictIdleConnections(0)
	tunnel.connectionBufferLock.RLock()
	remaining := len(tunnel.connectionBuffer)
	tunnel.connectionBufferLock.RUnlock()
	if remaining != 0 {
		t.Errorf("%d idle tunnel connections survived eviction; want 0", remaining)
	}
}
