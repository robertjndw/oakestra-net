package proxy

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTunDevice is a counting, in-memory TunDevice that honours the real
// adapter's header-offset convention (see tunHeaderOffset), so tests run
// without a real TUN device.
type fakeTunDevice struct {
	mu        sync.Mutex
	batchSize int
	readQueue [][]byte

	writeBatches int
	written      [][]byte
}

func (f *fakeTunDevice) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(bufs) && len(f.readQueue) > 0 {
		pkt := f.readQueue[0]
		f.readQueue = f.readQueue[1:]
		copy(bufs[n][tunHeaderOffset:], pkt)
		sizes[n] = len(pkt)
		n++
	}
	return n, nil
}

func (f *fakeTunDevice) WriteBatch(bufs [][]byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeBatches++
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[tunHeaderOffset:]...))
	}
	return len(bufs), nil
}

func (f *fakeTunDevice) BatchSize() int { return f.batchSize }
func (f *fakeTunDevice) Name() string   { return "faketun" }
func (f *fakeTunDevice) Close() error   { return nil }

// fakeTunnelSocket is a counting, in-memory TunnelSocket standing in for the
// listen socket.
type fakeTunnelSocket struct {
	mu    sync.Mutex
	queue [][]byte
}

func (f *fakeTunnelSocket) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(bufs) && len(f.queue) > 0 {
		pkt := f.queue[0]
		f.queue = f.queue[1:]
		copy(bufs[n], pkt)
		sizes[n] = len(pkt)
		n++
	}
	return n, nil
}

func (f *fakeTunnelSocket) WriteBatch(netip.AddrPort, [][]byte) (int, error) { return 0, nil }
func (f *fakeTunnelSocket) Close() error                                     { return nil }

// batchTestTunnel wires a real Datapath to the counting fakes above, so
// tests exercise real translation without a real TunDevice/TunnelSocket.
func batchTestTunnel(sock *fakeTunnelSocket, tun *fakeTunDevice) *Tunnel {
	tunnel := &Tunnel{
		sock:             sock,
		tun:              tun,
		connectionBuffer: make(map[netip.AddrPort]*tunnelConn),
	}
	tunnel.dp = fakeDatapathOn(nodeAIP, newFakeEnv())
	return tunnel
}

// TestIngoingBatchAmortisesSyscalls checks that N packets delivered in one
// TunnelSocket.ReadBatch reach the TUN device through exactly one
// TunDevice.WriteBatch call.
func TestIngoingBatchAmortisesSyscalls(t *testing.T) {
	const n = 16
	var queue [][]byte
	for i := 0; i < n; i++ {
		queue = append(queue, buildUDPv4(t, serverInstIP, clientNsIP, 80, 40000+i, []byte("payload")))
	}
	sock := &fakeTunnelSocket{queue: queue}
	tunDev := &fakeTunDevice{batchSize: n}
	tunnel := batchTestTunnel(sock, tunDev)

	batch := newIngoingBatch(tunDev.BatchSize())
	if err := tunnel.runIngoingBatch(batch); err != nil {
		t.Fatalf("runIngoingBatch: %v", err)
	}

	if tunDev.writeBatches != 1 {
		t.Errorf("WriteBatch called %d times for a single ReadBatch of %d packets; want 1", tunDev.writeBatches, n)
	}
	if len(tunDev.written) != n {
		t.Errorf("delivered %d packets; want %d", len(tunDev.written), n)
	}
	for i, got := range tunDev.written {
		if !bytes.Equal(got, queue[i]) {
			t.Errorf("packet %d delivered unchanged with no reverse mapping was mutated", i)
		}
	}
}

// TestIngoingBatchCorrectAtBatchSizeOne covers the no-IFF_VNET_HDR fallback
// (Darwin always, an older Linux kernel sometimes): every packet must still
// arrive at the TUN device, one WriteBatch call per read.
func TestIngoingBatchCorrectAtBatchSizeOne(t *testing.T) {
	packets := [][]byte{
		buildUDPv4(t, serverInstIP, clientNsIP, 80, 41000, []byte("one")),
		buildUDPv4(t, serverInstIP, clientNsIP, 80, 41001, []byte("two")),
		buildUDPv4(t, serverInstIP, clientNsIP, 80, 41002, []byte("three")),
	}
	sock := &fakeTunnelSocket{queue: append([][]byte(nil), packets...)}
	tunDev := &fakeTunDevice{batchSize: 1}
	tunnel := batchTestTunnel(sock, tunDev)

	batch := newIngoingBatch(tunDev.BatchSize())
	for i := range packets {
		if err := tunnel.runIngoingBatch(batch); err != nil {
			t.Fatalf("runIngoingBatch #%d: %v", i, err)
		}
	}

	if tunDev.writeBatches != len(packets) {
		t.Errorf("WriteBatch called %d times for %d single-packet reads; want %d",
			tunDev.writeBatches, len(packets), len(packets))
	}
	if len(tunDev.written) != len(packets) {
		t.Fatalf("delivered %d packets; want %d", len(tunDev.written), len(packets))
	}
	for i, got := range tunDev.written {
		if !bytes.Equal(got, packets[i]) {
			t.Errorf("packet %d corrupted at batch size 1", i)
		}
	}
}

// TestHandleIngoingOnlyDeliversOrDrops checks that Handle(Ingoing, ...) never
// returns ActionForward - runIngoingBatch relies on this - for a matched
// flow, an unmatched one, and a malformed packet.
func TestHandleIngoingOnlyDeliversOrDrops(t *testing.T) {
	dp := getFakeDatapath()
	dp.proxycache.Add(ConversionEntry{
		srcip:         mustAddr(clientNsIP),
		dstip:         mustAddr(serverNsIP),
		dstServiceIp:  mustAddr(serverVIP),
		srcInstanceIp: mustAddr(clientInstIP),
		dstInstanceIp: mustAddr(serverInstIP),
		srcport:       666,
		dstport:       80,
		protocol:      6,
	})

	cases := map[string][]byte{
		"matched flow":   buildTestPacketV4(t, serverInstIP, clientNsIP, 80, 666),
		"unmatched flow": buildTestPacketV4(t, "10.0.9.9", clientNsIP, 12345, 666),
		"malformed":      {0x45, 0x00},
		"udp, no transport": func() []byte {
			b := buildUDPv4(t, serverInstIP, clientNsIP, 80, 40000, nil)
			return b[:1] // truncate below a full IP header
		}(),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			action := dp.Handle(Ingoing, wire)
			if action.Kind == ActionForward {
				t.Errorf("Handle(Ingoing, ...) returned ActionForward for %q - runIngoingBatch cannot act on that", name)
			}
		})
	}
}

// fakeWgDevice is a minimal tun.Device fake for testing the real adapter's
// handling of tun.ErrTooManySegments without opening a real TUN device
// (which needs root).
type fakeWgDevice struct {
	calls int
}

func (d *fakeWgDevice) File() *os.File { return nil }

func (d *fakeWgDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.calls++
	if d.calls == 1 {
		return 0, tun.ErrTooManySegments
	}
	pkt := []byte{0x45, 0x00, 0x00, 0x14}
	n := copy(bufs[0][offset:], pkt)
	sizes[0] = n
	return 1, nil
}

func (d *fakeWgDevice) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (d *fakeWgDevice) MTU() (int, error)                            { return 1500, nil }
func (d *fakeWgDevice) Name() (string, error)                        { return "faketun", nil }
func (d *fakeWgDevice) Events() <-chan tun.Event                     { return nil }
func (d *fakeWgDevice) Close() error                                 { return nil }
func (d *fakeWgDevice) BatchSize() int                               { return 4 }

// TestWgTunDeviceErrTooManySegmentsIsNotFatal checks that a GSO superpacket
// wider than the read batch doesn't stop later reads from succeeding.
func TestWgTunDeviceErrTooManySegmentsIsNotFatal(t *testing.T) {
	w := newWgTunDevice(&fakeWgDevice{})
	bufs := [][]byte{make([]byte, tunHeaderOffset+64)}
	sizes := make([]int, 1)

	n, err := w.ReadBatch(bufs, sizes)
	if err != nil || n != 0 {
		t.Fatalf("first read: got (%d, %v); want (0, nil) - ErrTooManySegments must be absorbed, not propagated", n, err)
	}

	n, err = w.ReadBatch(bufs, sizes)
	if err != nil || n != 1 {
		t.Fatalf("second read: got (%d, %v); want (1, nil) - the device must still work after the error", n, err)
	}
}

// TestUDPTunnelSocketDualStackReceive checks that udpTunnelSocket's
// ipv6.PacketConn wrapper receives both IPv4 and IPv6 loopback datagrams
// over the same dual-stack listen socket.
func TestUDPTunnelSocketDualStackReceive(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	sock := newUDPTunnelSocket(conn)
	defer sock.Close()

	v4, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("dial v4: %v", err)
	}
	defer v4.Close()
	v6, err := net.DialUDP("udp6", nil, &net.UDPAddr{IP: net.ParseIP("::1"), Port: port})
	if err != nil {
		t.Fatalf("dial v6: %v", err)
	}
	defer v6.Close()

	if _, err := v4.Write([]byte("hello-v4")); err != nil {
		t.Fatalf("write v4: %v", err)
	}
	if _, err := v6.Write([]byte("hello-v6")); err != nil {
		t.Fatalf("write v6: %v", err)
	}

	bufs := [][]byte{make([]byte, 64), make([]byte, 64)}
	sizes := make([]int, 2)
	got := map[string]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < 2 && time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := sock.ReadBatch(bufs, sizes)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			t.Fatalf("ReadBatch: %v", err)
		}
		for i := 0; i < n; i++ {
			got[string(bufs[i][:sizes[i]])] = true
		}
	}

	if !got["hello-v4"] || !got["hello-v6"] {
		t.Fatalf("expected both v4 and v6 datagrams through one dual-stack socket; got %v", got)
	}
}
