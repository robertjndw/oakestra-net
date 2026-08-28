package proxy

import (
	"NetManager/proxy/iputils"
	"testing"
	"time"
)

// TestCachedRouteSurvivesUnchangedTable: while the translation table has not
// moved, a cached flow keeps its route and is tagged with the current
// generation, which is what lets the packet path skip rescanning every replica
// of the service on each hit.
func TestCachedRouteSurvivesUnchangedTable(t *testing.T) {
	proxy := getFakeTunnel()
	environment := proxy.environment.(*FakeEnv)

	if node := translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Fatalf("forwarded to %s; want %s", node, nodeBIP)
	}

	_, generation := environment.table.SearchByServiceIP(mustAddr(serverVIP))
	entry, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoTCP,
		mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(serverVIP), 443)
	if !ok {
		t.Fatal("the flow was not cached")
	}
	if entry.routeGen != generation {
		t.Errorf("cached route tagged with generation %d; table is at %d", entry.routeGen, generation)
	}

	if node := translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Errorf("second packet forwarded to %s; want the cached route %s", node, nodeBIP)
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
			proxy := getFakeTunnel()
			environment := proxy.environment.(*FakeEnv)

			translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))

			moved := tableEntry("serverapp", tc.node, serverNsIP, serverNsIPv6,
				serverVIP, serverVIPv6, serverInstIP, serverInstIPv6)
			moved.Nodeport = tc.port
			environment.replaceJob(t, moved.JobName, moved)

			pkt := parseTestPacket(t, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
			node, port, _, ok := proxy.outgoingProxy(&pkt)
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
	proxy := getFakeTunnel()
	environment := proxy.environment.(*FakeEnv)

	translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	environment.replaceJob(t, fixtureEntries[1].JobName)

	pkt := parseTestPacket(t, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	if _, _, _, ok := proxy.outgoingProxy(&pkt); ok {
		t.Error("a flow to a removed instance was still forwarded")
	}
}

// TestIdleTunnelConnectionsEvicted: tunnel sockets used to be removed only
// when a write to them failed, so talking to a node once kept its descriptor
// and socket buffer for the lifetime of the process.
func TestIdleTunnelConnectionsEvicted(t *testing.T) {
	proxy, _ := loopbackTunnel(t)

	proxy.handleOutgoing(buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443), false)

	proxy.connectionBufferLock.RLock()
	established := len(proxy.connectionBuffer)
	proxy.connectionBufferLock.RUnlock()
	if established != 1 {
		t.Fatalf("%d tunnel connections open; want 1", established)
	}

	// A connection used moments ago is not idle.
	proxy.evictIdleConnections(time.Hour)
	proxy.connectionBufferLock.RLock()
	kept := len(proxy.connectionBuffer)
	proxy.connectionBufferLock.RUnlock()
	if kept != 1 {
		t.Error("a connection in active use was evicted")
	}

	proxy.evictIdleConnections(0)
	proxy.connectionBufferLock.RLock()
	remaining := len(proxy.connectionBuffer)
	proxy.connectionBufferLock.RUnlock()
	if remaining != 0 {
		t.Errorf("%d idle tunnel connections survived eviction; want 0", remaining)
	}
}
