package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/env"
	"NetManager/proxy/iputils"
	"bytes"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// resolvingEnv reports a Service IP as unresolved until release is called,
// mimicking the window in which the real Environment is waiting on an MQTT
// table query.
type resolvingEnv struct {
	mu       sync.Mutex
	table    TableEntryCache.TableManager
	pending  map[netip.Addr]chan struct{}
	resolved map[netip.Addr]bool
	lookups  map[netip.Addr]int
}

func newResolvingEnv(entries ...TableEntryCache.TableEntry) *resolvingEnv {
	e := &resolvingEnv{
		table:    TableEntryCache.NewTableManager(),
		pending:  make(map[netip.Addr]chan struct{}),
		resolved: make(map[netip.Addr]bool),
		lookups:  make(map[netip.Addr]int),
	}
	for _, entry := range entries {
		if err := e.table.Add(entry); err != nil {
			panic(err)
		}
	}
	return e
}

func (e *resolvingEnv) GetTableEntryByServiceIP(addr netip.Addr) env.ServiceLookup {
	e.mu.Lock()
	e.lookups[addr]++
	resolved := e.resolved[addr]
	if !resolved {
		done, ok := e.pending[addr]
		if !ok {
			done = make(chan struct{})
			e.pending[addr] = done
		}
		e.mu.Unlock()
		return env.ServiceLookup{Resolving: done}
	}
	e.mu.Unlock()

	entries, generation := e.table.SearchByServiceIP(addr)
	return env.ServiceLookup{Entries: entries, Generation: generation}
}

func (e *resolvingEnv) GetTableEntryByNsIP(addr netip.Addr) (TableEntryCache.TableEntry, bool) {
	return e.table.SearchByNsIP(addr)
}

func (e *resolvingEnv) GetTableEntryByInstanceIP(net.IP) (TableEntryCache.TableEntry, bool) {
	return TableEntryCache.TableEntry{}, false
}

// release completes the resolution attempt for addr. succeed=false models an
// attempt that finished without finding anything.
func (e *resolvingEnv) release(addr netip.Addr, succeed bool) {
	e.mu.Lock()
	e.resolved[addr] = succeed
	done := e.pending[addr]
	delete(e.pending, addr)
	e.mu.Unlock()
	if done != nil {
		close(done)
	}
}

func (proxy *GoProxyTunnel) queuedFor(vip netip.Addr) int {
	proxy.replayLock.Lock()
	defer proxy.replayLock.Unlock()
	if queue, ok := proxy.replays[vip]; ok {
		return len(queue.packets)
	}
	return 0
}

func (proxy *GoProxyTunnel) replayState() (queues int, bytes int) {
	proxy.replayLock.Lock()
	defer proxy.replayLock.Unlock()
	return len(proxy.replays), proxy.replayBytes
}

// waitFor polls until cond holds, so tests never depend on a fixed sleep.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// coldTunnel is a loopback tunnel whose target service is not resolved yet.
func coldTunnel(t *testing.T) (*GoProxyTunnel, *net.UDPConn, *resolvingEnv) {
	t.Helper()
	proxy, listener := loopbackTunnel(t)

	resolving := newResolvingEnv()
	for _, entry := range loopbackEntries(t, listener) {
		if err := resolving.table.Add(entry); err != nil {
			t.Fatal(err)
		}
	}
	proxy.SetEnvironment(resolving)
	return proxy, listener, resolving
}

func loopbackEntries(t *testing.T, listener *net.UDPConn) []TableEntryCache.TableEntry {
	t.Helper()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	server := tableEntry("serverapp", "127.0.0.1", serverNsIP, serverNsIPv6,
		serverVIP, serverVIPv6, serverInstIP, serverInstIPv6)
	server.Nodeport = port
	other := tableEntry("otherapp", "127.0.0.1", otherNsIP, otherNsIPv6,
		otherVIP, otherVIPv6, otherInstIP, otherInstIPv6)
	other.Nodeport = port
	return []TableEntryCache.TableEntry{fixtureEntries[0], server, other}
}

// datagramPayload returns the UDP payload of a forwarded IPv4 packet.
func datagramPayload(t *testing.T, wire []byte) string {
	t.Helper()
	if len(wire) < 28 {
		t.Fatalf("packet too short to hold a UDP payload: %d bytes", len(wire))
	}
	return string(wire[28:])
}

// TestReplayPreservesOrder is the regression test for cold-start reordering.
// Every packet queued behind one unresolved Service IP used to get its own
// goroutine blocked on the same channel, so the order they resumed in - and
// therefore the order the datagrams left the node in - was the scheduler's
// choice, not the application's.
func TestReplayPreservesOrder(t *testing.T) {
	proxy, listener, resolving := coldTunnel(t)
	vip := mustAddr(serverVIP)

	const datagrams = 16
	payloads := make([]string, datagrams)
	for i := range payloads {
		payloads[i] = string(rune('a'+i)) + "-datagram"
		proxy.handleOutgoing(buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte(payloads[i])), true)
	}

	if got := proxy.queuedFor(vip); got != datagrams {
		t.Fatalf("queued %d packets; want %d", got, datagrams)
	}
	// One queue for the Service IP, not one per packet.
	if queues, _ := proxy.replayState(); queues != 1 {
		t.Fatalf("%d replay queues for a single Service IP; want 1", queues)
	}

	resolving.release(vip, true)

	for i, want := range payloads {
		if got := datagramPayload(t, readForwarded(t, listener)); got != want {
			t.Fatalf("datagram %d was %q; want %q - replay reordered the queue", i, got, want)
		}
	}

	waitFor(t, "the replay queue to be released", func() bool {
		queues, bytes := proxy.replayState()
		return queues == 0 && bytes == 0
	})
}

// TestReplaySeparateVIPsResolveIndependently: one Service IP resolving must
// not flush packets waiting on another.
func TestReplaySeparateVIPsResolveIndependently(t *testing.T) {
	proxy, listener, resolving := coldTunnel(t)

	proxy.handleOutgoing(buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("for-server")), true)
	proxy.handleOutgoing(buildUDPv4(t, clientNsIP, otherVIP, 40000, 53, []byte("for-other")), true)

	if queues, _ := proxy.replayState(); queues != 2 {
		t.Fatalf("%d replay queues; want one per Service IP", queues)
	}

	resolving.release(mustAddr(serverVIP), true)

	if got := datagramPayload(t, readForwarded(t, listener)); got != "for-server" {
		t.Errorf("forwarded %q; want the resolved Service IP's datagram", got)
	}
	waitFor(t, "only the resolved Service IP's queue to drain", func() bool {
		queues, _ := proxy.replayState()
		return queues == 1
	})
	if got := proxy.queuedFor(mustAddr(otherVIP)); got != 1 {
		t.Errorf("the unresolved Service IP has %d packets queued; want 1", got)
	}
}

// TestReplayQueueBounded: the queue is capped, and the cap is expressed in
// packets actually retained rather than pooled 64KiB buffers.
func TestReplayQueueBounded(t *testing.T) {
	proxy, _, _ := coldTunnel(t)

	for i := 0; i < maxReplayPacketsPerVIP*3; i++ {
		proxy.handleOutgoing(buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("x")), true)
	}

	if got := proxy.queuedFor(mustAddr(serverVIP)); got != maxReplayPacketsPerVIP {
		t.Errorf("queued %d packets; want the cap of %d", got, maxReplayPacketsPerVIP)
	}
	_, bytes := proxy.replayState()
	if bytes > maxReplayBytes {
		t.Errorf("retained %d bytes; cap is %d", bytes, maxReplayBytes)
	}
	// Retention is proportional to the packets held, not to the 64KiB read
	// buffer they arrived in.
	if bytes > maxReplayPacketsPerVIP*2048 {
		t.Errorf("retained %d bytes for %d small packets; retention should track packet length",
			bytes, maxReplayPacketsPerVIP)
	}
}

// TestReplayFailedResolutionReleasesQueue: an attempt that finishes without
// resolving anything must drop its queue rather than re-queue it forever.
func TestReplayFailedResolutionReleasesQueue(t *testing.T) {
	proxy, _, resolving := coldTunnel(t)

	for i := 0; i < 4; i++ {
		proxy.handleOutgoing(buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, []byte("x")), true)
	}
	resolving.release(mustAddr(serverVIP), false)

	waitFor(t, "the failed queue to be released", func() bool {
		queues, bytes := proxy.replayState()
		return queues == 0 && bytes == 0
	})
}

// TestReplayHoldsLaterFragmentsOfAColdDatagram: a fragmented datagram sent to
// a Service IP that is not resolved yet used to lose every fragment but the
// first. The first was retained for replay, while the rest reached
// forwardLaterFragment, found no translation state and were dropped - so the
// datagram could never reassemble no matter how the replay went.
func TestReplayHoldsLaterFragmentsOfAColdDatagram(t *testing.T) {
	proxy, listener, resolving := coldTunnel(t)
	vip := mustAddr(serverVIP)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	first, later := fragmentIPv4(t, wire, 1024)
	laterPayloadBefore := append([]byte(nil), later[20:]...)

	proxy.handleOutgoing(first, true)
	proxy.handleOutgoing(later, true)

	if got := proxy.queuedFor(vip); got != 2 {
		t.Fatalf("%d packets queued behind the unresolved Service IP; want both fragments", got)
	}

	resolving.release(vip, true)

	gotFirst := parseTestPacket(t, readForwarded(t, listener))
	if !gotFirst.IsFirstFragment() {
		t.Fatal("the first fragment must replay before the rest")
	}
	gotLater, ok := iputils.Parse(readForwarded(t, listener))
	if !ok {
		t.Fatal("the later fragment was never forwarded")
	}
	if gotLater.IsFirstFragment() {
		t.Fatal("expected the later fragment second")
	}

	// Both must be addressed identically, or the far end cannot reassemble
	// them into one datagram.
	if gotLater.SrcIP() != gotFirst.SrcIP() || gotLater.DstIP() != gotFirst.DstIP() {
		t.Errorf("fragments forwarded as %s -> %s and %s -> %s; they must match",
			gotFirst.SrcIP(), gotFirst.DstIP(), gotLater.SrcIP(), gotLater.DstIP())
	}
	if gotFirst.SrcIP() != mustAddr(clientInstIP) || gotFirst.DstIP() != mustAddr(serverNsIP) {
		t.Errorf("translated to %s -> %s; want %s -> %s",
			gotFirst.SrcIP(), gotFirst.DstIP(), clientInstIP, serverNsIP)
	}
	if got := ipv4HeaderChecksum(gotLater.Bytes()[:20]); got != 0 {
		t.Errorf("later fragment header checksum does not verify (residual %#04x)", got)
	}
	if !bytes.Equal(gotLater.Bytes()[20:], laterPayloadBefore) {
		t.Error("later fragment payload was modified")
	}
}

// TestLaterFragmentNeverStartsAResolution: a later fragment carries no
// transport ports, so it cannot drive a route lookup of its own. With nothing
// already waiting on its destination there is no first fragment for it to stay
// consistent with, and it must simply be dropped.
func TestLaterFragmentNeverStartsAResolution(t *testing.T) {
	proxy, _, _ := coldTunnel(t)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	_, later := fragmentIPv4(t, wire, 1024)

	proxy.handleOutgoing(later, true)

	if queues, bytes := proxy.replayState(); queues != 0 || bytes != 0 {
		t.Errorf("a lone later fragment created %d replay queues holding %d bytes; want none",
			queues, bytes)
	}
}

// TestReplayFragmentQueueRespectsBounds: fragments queue through the same
// bounded FIFO as everything else, so a flood cannot grow it without limit.
func TestReplayFragmentQueueRespectsBounds(t *testing.T) {
	proxy, _, _ := coldTunnel(t)

	wire := buildUDPv4(t, clientNsIP, serverVIP, 40000, 53, largePayload(2000))
	first, later := fragmentIPv4(t, wire, 1024)

	proxy.handleOutgoing(first, true)
	for range maxReplayPacketsPerVIP * 3 {
		proxy.handleOutgoing(append([]byte(nil), later...), true)
	}

	if got := proxy.queuedFor(mustAddr(serverVIP)); got != maxReplayPacketsPerVIP {
		t.Errorf("queued %d packets; want the cap of %d", got, maxReplayPacketsPerVIP)
	}
	if _, bytes := proxy.replayState(); bytes > maxReplayBytes {
		t.Errorf("retained %d bytes; cap is %d", bytes, maxReplayBytes)
	}
}
