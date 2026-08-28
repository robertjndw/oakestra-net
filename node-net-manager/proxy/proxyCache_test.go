package proxy

import (
	"NetManager/proxy/iputils"
	"testing"
)

// translate runs one outgoing packet through the proxy and returns the node it
// was forwarded to, leaving the flow in the cache.
func translate(t *testing.T, proxy *GoProxyTunnel, wire []byte) string {
	t.Helper()
	pkt := parseTestPacket(t, wire)
	dstNode, _, _, ok := proxy.outgoingProxy(&pkt)
	if !ok {
		t.Fatal("packet should have been proxied")
	}
	return dstNode.String()
}

// reverse runs one incoming packet through the proxy and returns the source
// address the local namespace ends up seeing.
func reverse(t *testing.T, proxy *GoProxyTunnel, wire []byte) string {
	t.Helper()
	pkt := parseTestPacket(t, wire)
	if !proxy.ingoingProxy(&pkt) {
		t.Fatal("packet should have matched a reverse cache entry")
	}
	return pkt.SrcIP().String()
}

// TestFlowCacheTwoServiceIPsSameSourcePort covers the collision the cache used
// to have: entries were considered identical on destination port alone within
// a source-port bucket, so opening a second flow from the same local socket to
// a different Service VIP on the same port destroyed the first mapping.
func TestFlowCacheTwoServiceIPsSameSourcePort(t *testing.T) {
	proxy := getFakeTunnel()

	if node := translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)); node != nodeBIP {
		t.Fatalf("first flow forwarded to %s; want %s", node, nodeBIP)
	}
	if node := translate(t, proxy, buildTestPacketV4(t, clientNsIP, otherVIP, 40000, 443)); node != nodeCIP {
		t.Fatalf("second flow forwarded to %s; want %s", node, nodeCIP)
	}

	// Both mappings must still be there.
	if _, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoTCP,
		mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(serverVIP), 443); !ok {
		t.Error("first flow's cache entry was destroyed by the second insert")
	}
	if _, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoTCP,
		mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(otherVIP), 443); !ok {
		t.Error("second flow's cache entry is missing")
	}
}

// TestFlowCacheReverseDistinguishesRemote is the damaging consequence of the
// same collision: a reply belonging to one Service VIP must never be
// reverse-translated as though it belonged to another.
func TestFlowCacheReverseDistinguishesRemote(t *testing.T) {
	proxy := getFakeTunnel()

	translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	translate(t, proxy, buildTestPacketV4(t, clientNsIP, otherVIP, 40000, 443))

	// Replies arrive from each target's instance IP (see TestRoundTrip).
	if got := reverse(t, proxy, buildTestPacketV4(t, serverInstIP, clientNsIP, 443, 40000)); got != serverVIP {
		t.Errorf("reply from %s reversed to %s; want %s", serverInstIP, got, serverVIP)
	}
	if got := reverse(t, proxy, buildTestPacketV4(t, otherInstIP, clientNsIP, 443, 40000)); got != otherVIP {
		t.Errorf("reply from %s reversed to %s; want %s", otherInstIP, got, otherVIP)
	}
}

// TestFlowCacheSeparatesProtocols covers TCP and UDP flows that are otherwise
// identical: same addresses, same ports. They are different flows.
func TestFlowCacheSeparatesProtocols(t *testing.T) {
	proxy := getFakeTunnel()

	translate(t, proxy, buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443))
	translate(t, proxy, buildUDPv4(t, clientNsIP, serverVIP, 40000, 443, []byte("hello")))

	tcpEntry, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoTCP,
		mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(serverVIP), 443)
	if !ok {
		t.Fatal("TCP flow's cache entry was destroyed by the UDP insert")
	}
	if tcpEntry.protocol != iputils.ProtoTCP {
		t.Errorf("TCP lookup returned a protocol-%d entry", tcpEntry.protocol)
	}

	udpEntry, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoUDP,
		mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(serverVIP), 443)
	if !ok {
		t.Fatal("UDP flow's cache entry is missing")
	}
	if udpEntry.protocol != iputils.ProtoUDP {
		t.Errorf("UDP lookup returned a protocol-%d entry", udpEntry.protocol)
	}

	// A reply must not cross over between them either.
	if _, found := proxy.proxycache.RetrieveByInstanceIp(iputils.ProtoTCP,
		mustAddr(clientNsIP), 40000, mustAddr(serverInstIP), 443); !found {
		t.Error("no reverse mapping for the TCP flow")
	}
	if _, found := proxy.proxycache.RetrieveByInstanceIp(101,
		mustAddr(clientNsIP), 40000, mustAddr(serverInstIP), 443); found {
		t.Error("a reply for an unrelated protocol matched a cached flow")
	}
}

// TestFlowCacheMultipleUDPDestinations is the ordinary UDP shape: one local
// socket talking to several Service VIPs at once.
func TestFlowCacheMultipleUDPDestinations(t *testing.T) {
	proxy := getFakeTunnel()

	vips := []struct{ vip, node string }{
		{serverVIP, nodeBIP},
		{otherVIP, nodeCIP},
		{clientVIP, nodeAIP},
	}
	for _, v := range vips {
		translate(t, proxy, buildUDPv4(t, clientNsIP, v.vip, 40000, 53, []byte("q")))
	}
	for _, v := range vips {
		entry, ok := proxy.proxycache.RetrieveByServiceIP(iputils.ProtoUDP,
			mustAddr(clientNsIP), mustAddr(clientInstIP), 40000, mustAddr(v.vip), 53)
		if !ok {
			t.Errorf("lost the cache entry for %s", v.vip)
			continue
		}
		if entry.dstNode.String() != v.node {
			t.Errorf("%s cached node = %s; want %s", v.vip, entry.dstNode, v.node)
		}
	}
}
