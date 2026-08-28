package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/proxy/iputils"
	"encoding/hex"
	"math/rand"
	"net"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type FakeEnv struct {
}

// used as example packets for testing
var ipv6Packet string = "600219310028063ffc000000000000000000000000000203fdff1000000000000000000000000001b98400502a8697ed00000000a002ff322a8900000204056e0402080a7fb1168c0000000001030307"

func (fakeenv *FakeEnv) GetTableEntryByServiceIP(ip net.IP) []TableEntryCache.TableEntry {
	entrytable := make([]TableEntryCache.TableEntry, 0)
	//If entry already available
	entry := TableEntryCache.TableEntry{
		Appname:          "a",
		Appns:            "a",
		Servicename:      "b",
		Servicenamespace: "b",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           net.ParseIP("10.0.0.1"),
		Nsip:             net.ParseIP("10.19.2.12"),
		Nsipv6:           net.ParseIP("fd00::12"),
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     TableEntryCache.Closest,
			Address:    net.ParseIP("10.30.255.255"),
			Address_v6: net.ParseIP("fdff:1000::ff"),
		},
			{
				IpType:     TableEntryCache.InstanceNumber,
				Address:    net.ParseIP("10.30.255.254"),
				Address_v6: net.ParseIP("fdff::fe"),
			}},
	}
	entrytable = append(entrytable, entry)
	return entrytable
}

func (fakeenv *FakeEnv) GetTableEntryByNsIP(ip net.IP) (TableEntryCache.TableEntry, bool) {
	entry := TableEntryCache.TableEntry{
		Appname:          "a",
		Appns:            "a",
		Servicename:      "c",
		Servicenamespace: "b",
		Instancenumber:   0,
		Cluster:          0,
		Nodeip:           net.ParseIP("10.0.0.1"),
		Nsip:             net.ParseIP("10.19.1.1"),
		Nsipv6:           net.ParseIP("fc00::1"),
		ServiceIP: []TableEntryCache.ServiceIP{{
			IpType:     TableEntryCache.Closest,
			Address:    net.ParseIP("10.30.255.252"),
			Address_v6: net.ParseIP("fdff:2000::fc"),
		},
			{
				IpType:     TableEntryCache.InstanceNumber,
				Address:    net.ParseIP("10.30.255.253"),
				Address_v6: net.ParseIP("fdff::fd"),
			}},
	}
	return entry, true
}

func (fakeenv *FakeEnv) GetTableEntryByInstanceIP(ip net.IP) (TableEntryCache.TableEntry, bool) {
	return TableEntryCache.TableEntry{}, false
}

func getFakeTunnel() *GoProxyTunnel {
	tunnel := &GoProxyTunnel{
		tunNetIP:    "10.19.1.254",
		ifce:        nil,
		isListening: true,
		ProxyIpSubnetwork: net.IPNet{
			IP:   net.ParseIP("10.30.0.0"),
			Mask: net.IPMask(net.ParseIP("255.255.0.0").To4()),
		},
		HostTUNDeviceName: "goProxyTun",
		TunnelPort:        50011,
		listenConnection:  nil,
		proxycache:        NewProxyCache(),
		randseed:          rand.New(rand.NewSource(42)),
		tunNetIPv6:        "fdfe::1337",
		ProxyIPv6Subnetwork: net.IPNet{
			IP:   net.ParseIP("fdff::"),
			Mask: net.CIDRMask(16, 128),
		},
		connectionBuffer: make(map[netip.AddrPort]*net.UDPConn),
	}
	tunnel.SetEnvironment(&FakeEnv{})
	return tunnel
}

// buildTestPacketV4/V6 build a valid, correctly-checksummed wire-format TCP
// packet for feeding into iputils.Parse - gopacket is only used here, as a
// test fixture builder, never by the production code in this package.
func buildTestPacketV4(t testing.TB, srcIP, dstIP string, srcPort, dstPort int) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		t.Fatalf("build IPv4 packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func buildTestPacketV6(t testing.TB, srcIP, dstIP string, srcPort, dstPort int) []byte {
	t.Helper()
	ip := &layers.IPv6{
		Version:    6,
		HopLimit:   64,
		NextHeader: layers.IPProtocolTCP,
		SrcIP:      net.ParseIP(srcIP),
		DstIP:      net.ParseIP(dstIP),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
	}
	_ = tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp); err != nil {
		t.Fatalf("build IPv6 packet: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func parseTestPacket(t *testing.T, wire []byte) iputils.Packet {
	t.Helper()
	pkt, ok := iputils.Parse(wire)
	if !ok || !pkt.HasTransport() {
		t.Fatalf("failed to parse test packet (ok=%v)", ok)
	}
	return pkt
}

func TestOutgoingProxy(t *testing.T) {
	proxy := getFakeTunnel()

	pkt := parseTestPacket(t, buildTestPacketV4(t, "10.19.1.1", "10.30.255.255", 666, 80))
	noProxyPkt := parseTestPacket(t, buildTestPacketV4(t, "10.19.1.1", "10.20.1.1", 666, 80))

	if _, _, proxied := proxy.outgoingProxy(&noProxyPkt); proxied {
		t.Error("Packet should not be proxied")
	}

	if _, _, proxied := proxy.outgoingProxy(&pkt); !proxied {
		t.Fatal("packet should have been proxied")
	}
	dstexpected := netip.MustParseAddr("10.19.2.12")
	if pkt.DstIP() != dstexpected {
		t.Error("dstIP = ", pkt.DstIP().String(), "; want =", dstexpected)
	}
}

func TestIngoingProxy(t *testing.T) {
	proxy := getFakeTunnel()

	//update proxy proxycache
	entry := ConversionEntry{
		srcip:         netip.MustParseAddr("10.19.1.15"),
		dstip:         netip.MustParseAddr("10.19.2.1"),
		dstServiceIp:  netip.MustParseAddr("10.30.255.255"),
		srcInstanceIp: netip.MustParseAddr("10.30.0.50"),
		srcport:       777,
		dstport:       666,
	}
	proxy.proxycache.Add(entry)

	pkt := parseTestPacket(t, buildTestPacketV4(t, "10.30.0.5", "10.19.1.15", 666, 777))
	noProxyPkt := parseTestPacket(t, buildTestPacketV4(t, "10.19.2.1", "10.19.1.12", 666, 80))

	if proxy.ingoingProxy(&noProxyPkt) {
		t.Error("Packet should not be proxied")
	}

	if !proxy.ingoingProxy(&pkt) {
		t.Fatal("packet should have matched the reverse cache entry")
	}
	srcexpected := netip.MustParseAddr("10.30.255.255")
	if pkt.SrcIP() != srcexpected {
		t.Error("srcIp = ", pkt.SrcIP().String(), "; want =", srcexpected)
	}
}

func TestOutgoingV6Proxy(t *testing.T) {
	proxy := getFakeTunnel()

	pkt := parseTestPacket(t, buildTestPacketV6(t, "fc00::1", "fdff:2000::ff", 666, 80))
	noProxyPkt := parseTestPacket(t, buildTestPacketV6(t, "fc00::1", "fd00::12", 666, 80))

	if _, _, proxied := proxy.outgoingProxy(&noProxyPkt); proxied {
		t.Error("Packet should not be proxied")
	}

	if _, _, proxied := proxy.outgoingProxy(&pkt); !proxied {
		t.Fatal("packet should have been proxied")
	}
	dstexpected := netip.MustParseAddr("fd00::12")
	if pkt.DstIP() != dstexpected {
		t.Error("dstIP = ", pkt.DstIP().String(), "; want =", dstexpected)
	}
}

func TestIngoingV6Proxy(t *testing.T) {
	proxy := getFakeTunnel()

	//update proxy proxycache
	entry := ConversionEntry{
		srcip:         netip.MustParseAddr("fc00::15"),
		dstip:         netip.MustParseAddr("fd00::12"),
		dstServiceIp:  netip.MustParseAddr("fdff:3000::ff"),
		srcInstanceIp: netip.MustParseAddr("fdff::12"),
		srcport:       777,
		dstport:       666,
	}
	proxy.proxycache.Add(entry)

	pkt := parseTestPacket(t, buildTestPacketV6(t, "fdff::12", "fc00::15", 666, 777))
	noProxyPkt := parseTestPacket(t, buildTestPacketV6(t, "fc00::1", "fd00::12", 666, 80))

	if proxy.ingoingProxy(&noProxyPkt) {
		t.Error("Packet should not be proxied")
	}

	if !proxy.ingoingProxy(&pkt) {
		t.Fatal("packet should have matched the reverse cache entry")
	}
	srcexpected := netip.MustParseAddr("fdff:3000::ff")
	if pkt.SrcIP() != srcexpected {
		t.Error("srcIp = ", pkt.SrcIP().String(), "; want =", srcexpected)
	}
}

func TestIPv6NextHeader(t *testing.T) {
	// keep this test in, since the IPv6 extension header walk seemed to mess
	// up the parsing of the packet afterwards. for future safety
	msg, _ := hex.DecodeString(ipv6Packet)
	pkt, ok := iputils.Parse(msg)
	if !ok {
		t.Fatal("failed to parse test packet")
	}
	if pkt.Protocol() != iputils.ProtoTCP {
		t.Error("Failed to detect TCP Header in IPv6 Next Header field.")
	}
}
