package proxy

import (
	"NetManager/proxy/iputils"
	"testing"
)

// translate runs one outgoing packet through the datapath and returns the
// node it was forwarded to, leaving the flow in the cache.
func translate(t *testing.T, dp *Datapath, wire []byte) string {
	t.Helper()
	pkt := parseTestPacket(t, wire)
	dstNode, _, _, ok := dp.outgoingProxy(&pkt)
	if !ok {
		t.Fatal("packet should have been proxied")
	}
	return dstNode.String()
}

// reverse runs one incoming packet through the datapath and returns the
// source address the local namespace ends up seeing.
func reverse(t *testing.T, dp *Datapath, wire []byte) string {
	t.Helper()
	pkt := parseTestPacket(t, wire)
	if !dp.ingoingProxy(&pkt) {
		t.Fatal("packet should have matched a reverse cache entry")
	}
	return pkt.SrcIP().String()
}

// cachedRoute looks up a flow's cached route the same way outgoingProxy does
// on a cache hit: against the flow's own current table generation, so a hit
// always takes the fast path regardless of what else has happened to the
// table in the meantime.
func cachedRoute(t *testing.T, dp *Datapath, protocol uint8, srcIP, srcInstanceIP, dstServiceIP string, srcPort, dstPort int) (Route, bool) {
	t.Helper()
	dst := mustAddr(dstServiceIP)
	lookup := dp.environment.GetTableEntryByServiceIP(dst)
	return dp.proxycache.Route(FlowKey{
		Protocol:      protocol,
		SrcIP:         mustAddr(srcIP),
		SrcInstanceIP: mustAddr(srcInstanceIP),
		DstServiceIP:  dst,
		SrcPort:       srcPort,
		DstPort:       dstPort,
	}, lookup)
}

// routeGenOf reads the generation tag off a cached entry directly, since the
// public Route API deliberately doesn't expose it - callers only ever need to
// know whether a cached route is current, not what generation tagged it.
func routeGenOf(t *testing.T, dp *Datapath, protocol uint8, srcIP, srcInstanceIP, dstServiceIP string, srcPort, dstPort int) uint64 {
	t.Helper()
	shard := shardOf(srcPort)
	dp.proxycache.locks[shard].Lock()
	defer dp.proxycache.locks[shard].Unlock()

	bucket := &dp.proxycache.cache[srcPort]
	for i := range bucket.entries {
		entry := &bucket.entries[i]
		if entry.protocol == protocol &&
			entry.dstport == dstPort &&
			entry.dstServiceIp == mustAddr(dstServiceIP) &&
			entry.srcip == mustAddr(srcIP) &&
			entry.srcInstanceIp == mustAddr(srcInstanceIP) {
			return entry.routeGen
		}
	}
	t.Fatal("no cached entry found")
	return 0
}

// TestFlowCacheTwoServiceIPsSameSourcePort: two flows from the same local
// socket to different Service VIPs on the same destination port must not
// collide in the same source-port bucket.
func TestFlowCacheTwoServiceIPsSameSourcePort(t *testing.T) {
	dp := getFakeDatapath()

	if node := translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Fatalf("first flow forwarded to %s; want %s", node, nodeBIP)
	}
	if node := translate(t, dp, buildTestPacketV4(t, clientNsIP, otherVIP, 40000, 443)); node != nodeCIP {
		t.Fatalf("second flow forwarded to %s; want %s", node, nodeCIP)
	}

	// Both mappings must still be there.
	if _, ok := cachedRoute(t, dp, iputils.ProtoTCP, clientNsIP, clientInstIP, serverVIP, 40000, 443); !ok {
		t.Error("first flow's cache entry was destroyed by the second insert")
	}
	if _, ok := cachedRoute(t, dp, iputils.ProtoTCP, clientNsIP, clientInstIP, otherVIP, 40000, 443); !ok {
		t.Error("second flow's cache entry is missing")
	}
}

// TestFlowCacheReverseDistinguishesRemote is the damaging consequence of the
// same collision: a reply belonging to one Service VIP must never be
// reverse-translated as though it belonged to another.
func TestFlowCacheReverseDistinguishesRemote(t *testing.T) {
	dp := getFakeDatapath()

	translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	translate(t, dp, buildTestPacketV4(t, clientNsIP, otherVIP, 40000, 443))

	// Replies arrive from each target's instance IP (see TestRoundTrip).
	if got := reverse(t, dp, buildTestPacketV4(t, serverInstIP, clientNsIP, 443, 40000)); got != serverVIP {
		t.Errorf("reply from %s reversed to %s; want %s", serverInstIP, got, serverVIP)
	}
	if got := reverse(t, dp, buildTestPacketV4(t, otherInstIP, clientNsIP, 443, 40000)); got != otherVIP {
		t.Errorf("reply from %s reversed to %s; want %s", otherInstIP, got, otherVIP)
	}
}

// TestFlowCacheSeparatesProtocols covers TCP and UDP flows that are otherwise
// identical: same addresses, same ports. They are different flows.
func TestFlowCacheSeparatesProtocols(t *testing.T) {
	dp := getFakeDatapath()

	translate(t, dp, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	translate(t, dp, buildUDPv4(t, clientNsIP, serverVIP, 40000, 443, []byte("hello")))

	if _, ok := cachedRoute(t, dp, iputils.ProtoTCP, clientNsIP, clientInstIP, serverVIP, 40000, 443); !ok {
		t.Fatal("TCP flow's cache entry was destroyed by the UDP insert")
	}
	if _, ok := cachedRoute(t, dp, iputils.ProtoUDP, clientNsIP, clientInstIP, serverVIP, 40000, 443); !ok {
		t.Fatal("UDP flow's cache entry is missing")
	}

	// A reply must not cross over between them either.
	if _, found := dp.proxycache.Reverse(iputils.ProtoTCP,
		mustAddr(clientNsIP), 40000, mustAddr(serverInstIP), 443); !found {
		t.Error("no reverse mapping for the TCP flow")
	}
	if _, found := dp.proxycache.Reverse(101,
		mustAddr(clientNsIP), 40000, mustAddr(serverInstIP), 443); found {
		t.Error("a reply for an unrelated protocol matched a cached flow")
	}
}

// TestFlowCacheMultipleUDPDestinations is the ordinary UDP shape: one local
// socket talking to several Service VIPs at once.
func TestFlowCacheMultipleUDPDestinations(t *testing.T) {
	dp := getFakeDatapath()

	vips := []struct{ vip, node string }{
		{serverVIP, nodeBIP},
		{otherVIP, nodeCIP},
		{clientVIP, nodeAIP},
	}
	for _, v := range vips {
		translate(t, dp, buildUDPv4(t, clientNsIP, v.vip, 40000, 53, []byte("q")))
	}
	for _, v := range vips {
		r, ok := cachedRoute(t, dp, iputils.ProtoUDP, clientNsIP, clientInstIP, v.vip, 40000, 53)
		if !ok {
			t.Errorf("lost the cache entry for %s", v.vip)
			continue
		}
		if r.DstNode.String() != v.node {
			t.Errorf("%s cached node = %s; want %s", v.vip, r.DstNode, v.node)
		}
	}
}
