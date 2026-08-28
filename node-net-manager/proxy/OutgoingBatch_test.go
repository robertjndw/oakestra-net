package proxy

import (
	"NetManager/TableEntryCache"
	"errors"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// fakeBatchWriter counts WriteBatch calls and records every packet handed to
// it, standing in for a real *ipv4.PacketConn/*ipv6.PacketConn (see
// tunnelConn.batch) without opening a socket. If err is set, every call
// fails after recording nothing sent - see TestOutgoingBatchOnePeerFailureDoesNotBlockOthers.
type fakeBatchWriter struct {
	calls   int
	written [][]byte
	err     error
}

func (f *fakeBatchWriter) WriteBatch(ms []ipv4.Message, flags int) (int, error) {
	f.calls++
	if f.err != nil {
		return 0, f.err
	}
	for _, m := range ms {
		f.written = append(f.written, append([]byte(nil), m.Buffers[0]...))
	}
	return len(ms), nil
}

// fakeConn returns a tunnelConn whose batched writes go through writer, with
// a real (if pointless) UDP socket behind conn - a write failure closes and
// redials that socket exactly as the real path does (see sendOverTunnelBatch),
// so conn has to be real even though nothing ever reads or writes through it
// directly in these tests.
func fakeConn(t testing.TB, writer batchWriter) *tunnelConn {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9})
	if err != nil {
		t.Fatalf("dial dummy conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &tunnelConn{conn: conn, batch: writer}
}

// TestOutgoingBatchAmortisesSyscalls is the acceptance check for this whole
// change: N packets bound for K distinct destinations in one TunDevice
// ReadBatch must reach the network through exactly K WriteBatch calls - one
// per destination - not N single writes and not one per packet.
func TestOutgoingBatchAmortisesSyscalls(t *testing.T) {
	sock := &fakeTunnelSocket{}
	tunDev := &fakeTunDevice{batchSize: 32}
	tunnel := batchTestTunnel(sock, tunDev)

	const toServer = 10
	const toOther = 6
	for i := 0; i < toServer; i++ {
		tunDev.readQueue = append(tunDev.readQueue, buildTestPacketV4(t, clientNsIP, serverVIP, 40000+i, 443))
	}
	for i := 0; i < toOther; i++ {
		tunDev.readQueue = append(tunDev.readQueue, buildTestPacketV4(t, clientNsIP, otherVIP, 50000+i, 443))
	}

	serverWriter := &fakeBatchWriter{}
	otherWriter := &fakeBatchWriter{}
	serverDst := netip.AddrPortFrom(mustAddr(nodeBIP), uint16(tunnelPort))
	otherDst := netip.AddrPortFrom(mustAddr(nodeCIP), uint16(tunnelPort))
	tunnel.connectionBuffer[serverDst] = fakeConn(t, serverWriter)
	tunnel.connectionBuffer[otherDst] = fakeConn(t, otherWriter)

	batch := newOutgoingBatch(tunDev.BatchSize())
	if err := tunnel.runOutgoingBatch(batch); err != nil {
		t.Fatalf("runOutgoingBatch: %v", err)
	}

	if serverWriter.calls != 1 {
		t.Errorf("WriteBatch called %d times for the %d packets bound for node B; want 1", serverWriter.calls, toServer)
	}
	if len(serverWriter.written) != toServer {
		t.Errorf("node B received %d packets; want %d", len(serverWriter.written), toServer)
	}
	if otherWriter.calls != 1 {
		t.Errorf("WriteBatch called %d times for the %d packets bound for node C; want 1", otherWriter.calls, toOther)
	}
	if len(otherWriter.written) != toOther {
		t.Errorf("node C received %d packets; want %d", len(otherWriter.written), toOther)
	}
}

// TestOutgoingBatchCorrectAtBatchSizeOne covers the no-batching fallback
// (Darwin always, an older Linux kernel sometimes): with room for exactly one
// packet per read, every packet still has to be grouped and sent correctly,
// just one ReadBatch call at a time rather than amortised across a read.
func TestOutgoingBatchCorrectAtBatchSizeOne(t *testing.T) {
	sock := &fakeTunnelSocket{}
	tunDev := &fakeTunDevice{batchSize: 1}
	tunnel := batchTestTunnel(sock, tunDev)

	packets := []struct {
		vip string
		dst string
	}{
		{serverVIP, nodeBIP},
		{otherVIP, nodeCIP},
		{serverVIP, nodeBIP},
	}
	for i, p := range packets {
		tunDev.readQueue = append(tunDev.readQueue, buildTestPacketV4(t, clientNsIP, p.vip, 41000+i, 443))
	}

	serverWriter := &fakeBatchWriter{}
	otherWriter := &fakeBatchWriter{}
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeBIP), uint16(tunnelPort))] = fakeConn(t, serverWriter)
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeCIP), uint16(tunnelPort))] = fakeConn(t, otherWriter)

	batch := newOutgoingBatch(tunDev.BatchSize())
	for i := range packets {
		if err := tunnel.runOutgoingBatch(batch); err != nil {
			t.Fatalf("runOutgoingBatch #%d: %v", i, err)
		}
	}

	if len(serverWriter.written) != 2 {
		t.Errorf("node B received %d packets; want 2", len(serverWriter.written))
	}
	if len(otherWriter.written) != 1 {
		t.Errorf("node C received %d packets; want 1", len(otherWriter.written))
	}
	// At batch size 1 there is exactly one packet - and so exactly one
	// destination - per read, so amortisation cannot kick in; each read still
	// has to produce its own WriteBatch call.
	if serverWriter.calls != 2 {
		t.Errorf("WriteBatch called %d times across node B's 2 single-packet reads; want 2", serverWriter.calls)
	}
	if otherWriter.calls != 1 {
		t.Errorf("WriteBatch called %d times across node C's 1 single-packet read; want 1", otherWriter.calls)
	}
}

// TestOutgoingBatchMixesLocalDeliveryAndForward proves the local-destination
// shortcut (ActionDeliver) still works when a batch also contains packets
// bound for a remote peer (ActionForward) - the two verdicts are handled by
// completely different code paths in runOutgoingBatch and must not interfere.
func TestOutgoingBatchMixesLocalDeliveryAndForward(t *testing.T) {
	const (
		selfVIP    = "10.30.255.240"
		selfNsIP   = "10.19.9.9"
		selfNsIPv6 = "fd00::90"
		selfVIPv6  = "fdff:2000::f0"
		selfInstIP = "10.30.255.241"
		selfInstv6 = "fdff::f1"
	)
	self := tableEntry("selfapp", nodeAIP, selfNsIP, selfNsIPv6, selfVIP, selfVIPv6, selfInstIP, selfInstv6)
	entries := append(append([]TableEntryCache.TableEntry{}, fixtureEntries...), self)
	env := newFakeEnv(entries...)

	sock := &fakeTunnelSocket{}
	tunDev := &fakeTunDevice{batchSize: 4}
	tunnel := &Tunnel{
		sock:             sock,
		tun:              tunDev,
		connectionBuffer: make(map[netip.AddrPort]*tunnelConn),
	}
	tunnel.dp = NewDatapath(env, mustAddr(nodeAIP), fixtureIPv4Prefix, fixtureIPv6Prefix, tunnel)

	remote := buildTestPacketV4(t, clientNsIP, serverVIP, 40000, 443)
	local := buildTestPacketV4(t, clientNsIP, selfVIP, 40001, 443)
	tunDev.readQueue = [][]byte{remote, local}

	serverWriter := &fakeBatchWriter{}
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeBIP), uint16(tunnelPort))] = fakeConn(t, serverWriter)

	batch := newOutgoingBatch(tunDev.BatchSize())
	if err := tunnel.runOutgoingBatch(batch); err != nil {
		t.Fatalf("runOutgoingBatch: %v", err)
	}

	if len(serverWriter.written) != 1 {
		t.Errorf("node B received %d packets; want 1 (the remote-bound one)", len(serverWriter.written))
	}
	if tunDev.writeBatches != 1 {
		t.Errorf("TUN WriteBatch called %d times; want 1 for the locally-delivered packet", tunDev.writeBatches)
	}
	if len(tunDev.written) != 1 {
		t.Fatalf("TUN device delivered %d packets; want 1", len(tunDev.written))
	}
}

// TestOutgoingBatchOnePeerFailureDoesNotBlockOthers proves that one
// destination's write failing does not stop the rest of the batch's other
// destinations from being delivered - the groups in runOutgoingBatch's active
// list are independent send attempts, not one all-or-nothing operation.
func TestOutgoingBatchOnePeerFailureDoesNotBlockOthers(t *testing.T) {
	sock := &fakeTunnelSocket{}
	tunDev := &fakeTunDevice{batchSize: 4}
	tunnel := batchTestTunnel(sock, tunDev)

	tunDev.readQueue = [][]byte{
		buildTestPacketV4(t, clientNsIP, serverVIP, 42000, 443), // -> node B, will fail
		buildTestPacketV4(t, clientNsIP, otherVIP, 42001, 443),  // -> node C, must still succeed
	}

	failing := &fakeBatchWriter{err: errors.New("boom")}
	okWriter := &fakeBatchWriter{}
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeBIP), uint16(tunnelPort))] = fakeConn(t, failing)
	tunnel.connectionBuffer[netip.AddrPortFrom(mustAddr(nodeCIP), uint16(tunnelPort))] = fakeConn(t, okWriter)

	batch := newOutgoingBatch(tunDev.BatchSize())
	if err := tunnel.runOutgoingBatch(batch); err != nil {
		t.Fatalf("runOutgoingBatch: %v", err)
	}

	if failing.calls == 0 {
		t.Error("the failing destination was never attempted")
	}
	if len(okWriter.written) != 1 {
		t.Errorf("the healthy destination received %d packets; want 1 - a sibling failure must not block it", len(okWriter.written))
	}
}

// TestNewTunnelConnPicksAddressFamily proves which of ipv4/ipv6 backs a
// dialled tunnelConn's batched writer: a socket net.DialUDP dials to a
// specific remote address is single-family, unlike the always-dual-stack
// listen socket (see udpTunnelSocket), and a node can have peers of both
// kinds - so the wrapper has to be chosen per connection from dst's own
// family, not fixed for the whole Tunnel.
//
// Sending real datagrams over both an IPv4 and an IPv6 loopback peer and
// reading both back, plus asserting the concrete wrapper type each got, is
// the proof: guessing the family backwards would either fail to construct a
// working connection or silently pick the wrong wrapper.
func TestNewTunnelConnPicksAddressFamily(t *testing.T) {
	v4Listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen v4: %v", err)
	}
	defer v4Listener.Close()
	v6Listener, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("::1"), Port: 0})
	if err != nil {
		t.Fatalf("listen v6: %v", err)
	}
	defer v6Listener.Close()

	v4Dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(v4Listener.LocalAddr().(*net.UDPAddr).Port))
	v6Dst := netip.AddrPortFrom(netip.MustParseAddr("::1"), uint16(v6Listener.LocalAddr().(*net.UDPAddr).Port))

	tunnel := getFakeTunnel()

	batch := newOutgoingBatch(4)
	tunnel.sendOverTunnelBatch(v4Dst, [][]byte{[]byte("hello-v4")}, batch, 0)
	tunnel.sendOverTunnelBatch(v6Dst, [][]byte{[]byte("hello-v6")}, batch, 0)

	tunnel.connectionBufferLock.RLock()
	v4Conn := tunnel.connectionBuffer[v4Dst]
	v6Conn := tunnel.connectionBuffer[v6Dst]
	tunnel.connectionBufferLock.RUnlock()

	if v4Conn == nil || v6Conn == nil {
		t.Fatalf("expected both destinations to have dialled a connection")
	}
	if _, ok := v4Conn.batch.(*ipv4.PacketConn); !ok {
		t.Errorf("v4 peer's tunnelConn.batch is %T; want *ipv4.PacketConn", v4Conn.batch)
	}
	if _, ok := v6Conn.batch.(*ipv6.PacketConn); !ok {
		t.Errorf("v6 peer's tunnelConn.batch is %T; want *ipv6.PacketConn", v6Conn.batch)
	}

	if got := readUDP(t, v4Listener); got != "hello-v4" {
		t.Errorf("v4 listener got %q; want %q", got, "hello-v4")
	}
	if got := readUDP(t, v6Listener); got != "hello-v6" {
		t.Errorf("v6 listener got %q; want %q", got, "hello-v6")
	}
}

func readUDP(t testing.TB, conn *net.UDPConn) string {
	t.Helper()
	buf := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}
