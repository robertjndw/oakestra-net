package proxy

import (
	"NetManager/logger"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// packetReadBufferSize is how much is read per packet off the TUN device or
// UDP socket - generous headroom over any realistic MTU, but deliberately
// NOT the same constant as socketBufferSize below: that one sizes the
// kernel's socket buffer, and reusing it here would size every pooled
// per-packet buffer at multiple megabytes for no benefit.
const packetReadBufferSize = 64 * 1024

// batchPacketCap is the per-packet payload capacity of both batched read
// loops' buffers (see ingoingBatch/outgoingBatch). Unlike
// packetReadBufferSize's sync.Pool, which grows and shrinks with demand,
// these are fixed arrays of TunDevice.BatchSize() buffers held for the
// process lifetime - so this size sets a hard memory floor: at Linux's
// typical BatchSize() of 128, packetReadBufferSize's 64KiB would pin 8MiB per
// loop for datagrams that cannot exceed the MTU by much. 9000 bytes covers
// the jumbo-frame ceiling widely used by cloud VPCs (AWS, GCP) - comfortably
// above any MTU this proxy is likely configured with - while keeping the
// worst case (128 * (tunHeaderOffset+9000)) to about 1.1MiB per loop.
const batchPacketCap = 9000

// socketBufferSize is the requested SO_RCVBUF/SO_SNDBUF size for the tunnel
// UDP sockets. Larger than the previous 64KB so a burst of packets has room
// to sit in the kernel queue instead of being dropped while this process is
// busy translating the previous one.
const socketBufferSize = 4 * 1024 * 1024

// Idle tunnel sockets are closed rather than kept for the process lifetime:
// every distinct peer node ever talked to would otherwise hold a descriptor
// and a socket buffer allocation forever.
const (
	connectionIdleTimeout   = 5 * time.Minute
	connectionSweepInterval = time.Minute
)

// Config
type Configuration struct {
	HostTUNDeviceName         string `json:"HostTunnelDeviceName"`
	ProxySubnetwork           string `json:"ProxySubnetwork"`
	ProxySubnetworkMask       string `json:"ProxySubnetworkMask"`
	TunNetIP                  string `json:"TunnelIP"`
	TunnelPort                int    `json:"TunnelPort"`
	Mtusize                   int    `json:"MTUSize"`
	TunNetIPv6                string `json:"TunNetIPv6"`
	ProxySubnetworkIPv6       string `json:"ProxySubnetworkIPv6"`
	ProxySubnetworkIPv6Prefix int    `json:"ProxySubnetworkIPv6Prefix"`
}

// batchWriter is the family-independent surface of *ipv4.PacketConn and
// *ipv6.PacketConn a tunnelConn needs. ipv4.Message and ipv6.Message are both
// aliases of the same underlying type (golang.org/x/net's internal
// socket.Message), so one interface expressed in either package's Message
// type is satisfied by both wrappers - there is no family-specific method set
// to bridge here, just two constructors (see newTunnelConn).
type batchWriter interface {
	WriteBatch(ms []ipv4.Message, flags int) (int, error)
}

// tunnelConn is one UDP socket to a peer node, plus the coarse timestamp the
// idle sweeper uses to decide when to close it and a batched writer for
// grouped outgoing sends (see Tunnel.sendOverTunnelBatch).
type tunnelConn struct {
	conn     *net.UDPConn
	lastUsed atomic.Int64
	// batch is conn wrapped for WriteBatch - see newTunnelConn for why the
	// wrapper's family has to match dst rather than always being one or the
	// other.
	batch batchWriter
}

// Tunnel owns the TUN device, the listen socket, the per-peer connection pool
// and its idle eviction, the read loops and the lifecycle channels - every bit
// of actual socket/TUN I/O. It performs no translation decisions itself;
// those belong to Datapath, which it drives via Handle/Emit.
type Tunnel struct {
	dp *Datapath
	// sock is the tunnel's listen socket - only ever used for the batched
	// ingoing read (see ingoingLoop). Sending to a peer still goes through
	// connectionBuffer's per-peer dialled connections below (see
	// sendOverTunnelBatch): unifying the two so a single sendmmsg could cover
	// every destination at once is deliberately out of scope, not an
	// oversight - it would source tunnel traffic from the listen port instead
	// of an ephemeral one, which firewalls and NAT in real deployments treat
	// very differently.
	sock              TunnelSocket
	connectionBuffer  map[netip.AddrPort]*tunnelConn
	tun               TunDevice
	finishChannel     chan bool
	errorChannel      chan error
	stopChannel       chan bool
	HostTUNDeviceName string
	tunNetIPv6        string
	tunNetIP          string
	mtu               int
	TunnelPort        int
	// connectionBufferLock guards only connectionBuffer. net.UDPConn is
	// itself safe for concurrent use, so nothing else needs to hold this
	// while a packet is actually being written.
	connectionBufferLock sync.RWMutex
	isListening          bool
}

// packetBufPool holds MTU-sized buffers for Emit's ActionDeliver copies (the
// replay goroutine's only path back to the TUN device), so it doesn't
// allocate one per packet. Both batched read loops have their own
// fixed-size pool instead - see ingoingBatch/outgoingBatch - since their
// buffers need to stay put across a whole batch rather than being returned to
// a shared pool after each packet. Buffers here are always pooled at full
// capacity and resliced by the caller after a read.
//
// Every buffer here reserves tunHeaderOffset bytes up front - see TunDevice -
// since these are also the buffers Emit's ActionDeliver case writes back to
// the TUN device.
var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, tunHeaderOffset+packetReadBufferSize)
		return &b
	},
}

func getPacketBuf() *[]byte {
	return packetBufPool.Get().(*[]byte)
}

func putPacketBuf(b *[]byte) {
	*b = (*b)[:cap(*b)]
	packetBufPool.Put(b)
}

// Emit performs the Action the Datapath decided on: dropping it, writing it
// to the TUN device, or sending it over the tunnel to another node. Today its
// only caller is the replay goroutine inside Datapath (see Sink) - both
// synchronous read loops call Handle directly and batch the result
// themselves instead (see runIngoingBatch, runOutgoingBatch) - so, unlike
// those, it cannot assume action.Packet already sits in a buffer with the TUN
// device's header room reserved (a replayed packet is a bare copy - see
// Datapath.enqueueReplayLocked) and always copies onto a pooled buffer that
// does before writing.
func (t *Tunnel) Emit(action Action) {
	switch action.Kind {
	case ActionDrop:
		return
	case ActionDeliver:
		buf := getPacketBuf()
		n := copy((*buf)[tunHeaderOffset:], action.Packet)
		if _, err := t.tun.WriteBatch([][]byte{(*buf)[:tunHeaderOffset+n]}); err != nil {
			logger.ErrorLogger().Println(err)
		}
		putPacketBuf(buf)
	case ActionForward:
		t.sendOverTunnel(action.Dst, action.Packet, 0)
	}
}

// Enable listening to outgoing packets
// if the goroutine must be stopped, send true to the stop channel
// when the channels finish listening a "true" is sent back to the finish channel
// in case of fatal error they are routed back to the err channel
func (t *Tunnel) tunOutgoingListen() {
	readerror := make(chan error)

	// async reader+processor
	go t.outgoingLoop(readerror)

	t.isListening = true
	logger.InfoLogger().Println("GoProxyTunnel outgoing listening started")
	for {
		select {
		case stopmsg := <-t.stopChannel:
			if stopmsg {
				logger.DebugLogger().Println("Outgoing listener received stop message")
				t.isListening = false
				t.finishChannel <- true
				return
			}
		case errormsg := <-readerror:
			t.errorChannel <- errormsg
		}
	}
}

// Enable listening for ingoing packets
// if the goroutine must be stopped, send true to the stop channel
// when the channels finish listening a "true" is sent back to the finish channel
// in case of fatal error they are routed back to the err channel
func (t *Tunnel) tunIngoingListen() {
	readerror := make(chan error)

	// async reader+processor
	go t.ingoingLoop(readerror)

	t.isListening = true
	logger.InfoLogger().Println("GoProxyTunnel ingoing listening started")
	for {
		select {
		case stopmsg := <-t.stopChannel:
			if stopmsg {
				logger.DebugLogger().Println("Ingoing listener received stop message")
				_ = t.sock.Close()
				t.isListening = false
				t.finishChannel <- true
				return
			}
		case errormsg := <-readerror:
			t.errorChannel <- errormsg
		}
	}
}

// outgoingBatchGroup collects the packets one outgoingBatch grouped for a
// single remote destination, so sendOverTunnelBatch can resolve dst's
// tunnelConn once and write the whole group instead of once per packet.
type outgoingBatchGroup struct {
	dst  netip.AddrPort
	gen  uint64
	bufs [][]byte
}

// outgoingBatch holds the fixed set of buffers the outgoing loop reuses
// across every read - mirroring ingoingBatch, see batchPacketCap - plus the
// state that groups one read's ActionForward packets by destination. Unlike
// the ingoing side, one read can be bound for several different peers, so
// grouping is the whole point here: groupOf and groups only ever grow (never
// get cleared or reallocated) as new destinations are seen, and gen
// distinguishes "touched this batch" from "leftover from an older one"
// without walking either structure between reads - see group.
type outgoingBatch struct {
	envelopes [][]byte
	bufs      [][]byte
	sizes     []int

	deliverable [][]byte // ActionDeliver packets, collected for one tun.WriteBatch

	groupOf map[netip.AddrPort]int // dst -> index into groups
	groups  []outgoingBatchGroup
	active  []int // indices into groups touched this batch, in first-seen order
	gen     uint64

	msgs []ipv4.Message // scratch for sendOverTunnelBatch - see writeMessages
}

func newOutgoingBatch(size int) *outgoingBatch {
	if size < 1 {
		size = 1
	}
	b := &outgoingBatch{
		envelopes:   make([][]byte, size),
		bufs:        make([][]byte, size),
		sizes:       make([]int, size),
		deliverable: make([][]byte, 0, size),
		groupOf:     make(map[netip.AddrPort]int),
	}
	for i := range b.envelopes {
		b.envelopes[i] = make([]byte, tunHeaderOffset+batchPacketCap)
		// Unlike ingoingBatch.bufs (fed to TunnelSocket.ReadBatch, which has
		// no header offset to apply), bufs here is fed straight to
		// TunDevice.ReadBatch, whose contract is the full envelope - offset
		// and all, see TunDevice - since the offset is applied inside it.
		b.bufs[i] = b.envelopes[i]
	}
	return b
}

// group appends packet to the batch's group for dst, creating or recycling a
// group slot as needed, and records dst as touched this batch (see active).
// packet aliases one of b.envelopes' buffers, so it stays valid only until
// the next ReadBatch - callers must drain active before then.
func (b *outgoingBatch) group(dst netip.AddrPort, packet []byte) {
	idx, exists := b.groupOf[dst]
	if exists && b.groups[idx].gen == b.gen {
		b.groups[idx].bufs = append(b.groups[idx].bufs, packet)
		return
	}
	if !exists {
		idx = len(b.groups)
		b.groups = append(b.groups, outgoingBatchGroup{})
		b.groupOf[dst] = idx
	}
	g := &b.groups[idx]
	g.dst = dst
	g.gen = b.gen
	g.bufs = append(g.bufs[:0], packet)
	b.active = append(b.active, idx)
}

// writeMessages resizes b.msgs to len(bufs) and points each message's single
// buffer at the corresponding packet. Addr is left nil throughout - every
// destination here is a connected tunnelConn (see newTunnelConn), so
// WriteBatch always sends to the peer the socket is already dialled to. Both
// the outer slice and each message's inner Buffers slice are reused across
// every call: sendOverTunnelBatch only ever runs on the single outgoing-loop
// goroutine, so nothing here needs to be safe for concurrent use.
func (b *outgoingBatch) writeMessages(bufs [][]byte) []ipv4.Message {
	for len(b.msgs) < len(bufs) {
		b.msgs = append(b.msgs, ipv4.Message{Buffers: make([][]byte, 1)})
	}
	msgs := b.msgs[:len(bufs)]
	for i, buf := range bufs {
		msgs[i].Buffers[0] = buf
		msgs[i].Addr = nil
		msgs[i].N = 0
	}
	return msgs
}

// runOutgoingBatch performs one read-decide-send cycle: one TunDevice read,
// Datapath.Handle for everything it returned, and - the whole point of
// batching - at most one TunDevice.WriteBatch for whatever needed local
// delivery plus one tunnel write per distinct remote destination, instead of
// one write per packet either way. It returns the read error, if any; a
// send/write error is only logged here, matching Emit's existing behaviour
// for the same case (sendOverTunnelBatch itself still redials and retries a
// failed send - see there).
func (t *Tunnel) runOutgoingBatch(b *outgoingBatch) error {
	n, err := t.tun.ReadBatch(b.bufs, b.sizes)
	if err != nil {
		return err
	}

	b.deliverable = b.deliverable[:0]
	b.active = b.active[:0]
	b.gen++

	for i := 0; i < n; i++ {
		packet := b.envelopes[i][tunHeaderOffset : tunHeaderOffset+b.sizes[i]]
		switch action := t.dp.Handle(Outgoing, packet); action.Kind {
		case ActionDrop:
		case ActionDeliver:
			// action.Packet aliases packet (see Handle's contract), and packet
			// already sits in a buffer with the TUN device's header room
			// reserved before it - unlike Emit's ActionDeliver case, which
			// copies for exactly that reason, this can go straight back with
			// no copy.
			b.deliverable = append(b.deliverable, b.envelopes[i][:tunHeaderOffset+b.sizes[i]])
		case ActionForward:
			b.group(action.Dst, action.Packet)
		default:
			// Handle(Outgoing, ...) only ever returns Deliver, Forward or
			// Drop - never trust that silently, since acting on anything else
			// here would mean grouping garbage into a send.
			logger.ErrorLogger().Println("outgoing datapath returned an unexpected action:", action.Kind)
		}
	}

	if len(b.deliverable) > 0 {
		if _, err := t.tun.WriteBatch(b.deliverable); err != nil {
			logger.ErrorLogger().Println(err)
		}
	}

	// Groups are drained after both the read and the delivery write are done
	// with the batch's buffers - sendOverTunnelBatch may block briefly on
	// redial, and holding TUN writes on that would only slow this loop down,
	// not the groups it hasn't gotten to yet.
	for _, idx := range b.active {
		g := &b.groups[idx]
		t.sendOverTunnelBatch(g.dst, g.bufs, b, 0)
	}
	return nil
}

// outgoingLoop reads batches of packets off the TUN device and, per read,
// forwards them with as few writes as the batch's shape allows: one
// TunDevice.WriteBatch for everything needing local delivery, and one tunnel
// write per distinct remote destination - see runOutgoingBatch.
func (t *Tunnel) outgoingLoop(errchannel chan<- error) {
	batch := newOutgoingBatch(t.tun.BatchSize())
	for {
		if err := t.runOutgoingBatch(batch); err != nil {
			errchannel <- err
		}
	}
}

// ingoingBatch holds the fixed set of buffers the ingoing loop reuses across
// every read - see batchPacketCap for why it isn't sized like
// packetReadBufferSize's pool. envelopes are the full buffers (headroom included);
// bufs are the same buffers pre-sliced past the headroom, which is all
// TunnelSocket ever needs to see.
type ingoingBatch struct {
	envelopes   [][]byte
	bufs        [][]byte
	sizes       []int
	deliverable [][]byte
}

func newIngoingBatch(size int) *ingoingBatch {
	if size < 1 {
		size = 1
	}
	b := &ingoingBatch{
		envelopes:   make([][]byte, size),
		bufs:        make([][]byte, size),
		sizes:       make([]int, size),
		deliverable: make([][]byte, 0, size),
	}
	for i := range b.envelopes {
		b.envelopes[i] = make([]byte, tunHeaderOffset+batchPacketCap)
		b.bufs[i] = b.envelopes[i][tunHeaderOffset:]
	}
	return b
}

// runIngoingBatch performs one read-decide-write cycle: one TunnelSocket
// read, Datapath.Handle for everything it returned, and - the whole point of
// batching - at most one TunDevice write for everything that needed
// delivering, instead of one write per packet. It returns the read error, if
// any; a write error is only logged, matching Emit's existing behaviour for
// the same case.
func (t *Tunnel) runIngoingBatch(b *ingoingBatch) error {
	n, err := t.sock.ReadBatch(b.bufs, b.sizes)
	if err != nil {
		return err
	}

	b.deliverable = b.deliverable[:0]
	for i := 0; i < n; i++ {
		packet := b.envelopes[i][tunHeaderOffset : tunHeaderOffset+b.sizes[i]]
		switch action := t.dp.Handle(Ingoing, packet); action.Kind {
		case ActionDrop:
		case ActionDeliver:
			b.deliverable = append(b.deliverable, b.envelopes[i][:tunHeaderOffset+b.sizes[i]])
		default:
			// Handle(Ingoing, ...) only ever returns Deliver or Drop - never
			// trust that silently, since acting on a Forward here would mean
			// writing a still-addressed-for-the-network packet to the TUN
			// device instead of sending it.
			logger.ErrorLogger().Println("ingoing datapath returned an unexpected action:", action.Kind)
		}
	}

	if len(b.deliverable) > 0 {
		if _, err := t.tun.WriteBatch(b.deliverable); err != nil {
			logger.ErrorLogger().Println(err)
		}
	}
	return nil
}

// ingoingLoop reads batches of packets off the tunnel UDP socket and, for
// whatever needs delivering to the TUN device, writes them back in a single
// batched call - see runIngoingBatch.
func (t *Tunnel) ingoingLoop(errchannel chan<- error) {
	batch := newIngoingBatch(t.tun.BatchSize())
	for {
		if err := t.runIngoingBatch(batch); err != nil {
			errchannel <- err
		}
	}
}

// connFor resolves dst's tunnelConn, dialling and storing a new one if none
// exists yet. Shared by sendOverTunnel and sendOverTunnelBatch so both agree
// on how a peer connection comes into existence.
func (t *Tunnel) connFor(dst netip.AddrPort) (*tunnelConn, error) {
	t.connectionBufferLock.RLock()
	con, exist := t.connectionBuffer[dst]
	t.connectionBufferLock.RUnlock()
	if exist {
		return con, nil
	}
	return t.dialAndStore(dst)
}

// evictDeadConn removes con from connectionBuffer if it is still the entry
// for dst, so dialAndStore's double-check doesn't just hand a failed
// connection straight back. Guarded on identity, as in evictIdleConnections:
// another goroutine may have already replaced it with a live connection by
// the time a failed write gets here.
func (t *Tunnel) evictDeadConn(dst netip.AddrPort, con *tunnelConn) {
	t.connectionBufferLock.Lock()
	if t.connectionBuffer[dst] == con {
		delete(t.connectionBuffer, dst)
	}
	t.connectionBufferLock.Unlock()
}

// sendOverTunnel sends packetBytes to dst over the tunnel. The local-delivery
// shortcut and the invalid-host check happen in Datapath.forwardResult before
// an Action ever reaches here, so dst is always a real remote peer. It's a
// single-packet call onto sendOverTunnelBatch's connect/write/retry logic;
// unlike runOutgoingBatch's calls, this can run on several replay goroutines
// at once (see retainForReplay), so it can't share runOutgoingBatch's
// scratch outgoingBatch and gets its own per-call instead.
func (t *Tunnel) sendOverTunnel(dst netip.AddrPort, packetBytes []byte, attemptNumber int) {
	t.sendOverTunnelBatch(dst, [][]byte{packetBytes}, &outgoingBatch{}, attemptNumber)
}

// sendOverTunnelBatch sends bufs to dst, resolving dst's tunnelConn once for
// the whole group instead of once per packet - the amortisation this whole
// change is for - and writing them with as few WriteBatch calls as the
// connection's platform allows (see batchWriter). scratch is where messages
// are built for the underlying WriteBatch call; the caller (runOutgoingBatch)
// owns it and reuses it across every destination and every batch, so this
// never allocates in steady state.
//
// A write failure redials exactly as sendOverTunnel does: the dead connection
// is evicted, a fresh one is dialled, and whatever of the group didn't make
// it out yet is retried on it, up to the same 10-retry cap - so one peer
// being down costs that peer's group some latency, never the other groups in
// the same batch, which are already independent loop iterations by the time
// this runs (see runOutgoingBatch). A platform whose WriteBatch can only ever
// accept one message per call (see ipv4/ipv6's doc on that) is not a
// failure - the loop just keeps calling it until the group drains.
func (t *Tunnel) sendOverTunnelBatch(dst netip.AddrPort, bufs [][]byte, scratch *outgoingBatch, attemptNumber int) {
	if attemptNumber > 10 || len(bufs) == 0 {
		return
	}

	con, err := t.connFor(dst)
	if err != nil {
		return
	}
	con.lastUsed.Store(coarseClock.Load())

	for len(bufs) > 0 {
		sent, err := con.batch.WriteBatch(scratch.writeMessages(bufs), 0)
		bufs = bufs[sent:]
		if err == nil {
			if sent == 0 {
				// WriteBatch's contract only promises this can happen on
				// error - treat a silent no-op the same way rather than
				// spinning on the rest of the group forever.
				return
			}
			continue
		}

		_ = con.conn.Close()
		logger.ErrorLogger().Println(err)
		t.evictDeadConn(dst, con)

		if _, err := t.dialAndStore(dst); err != nil {
			return
		}
		// Retry only what didn't make it out before the failure.
		t.sendOverTunnelBatch(dst, bufs, scratch, attemptNumber+1)
		return
	}
}

// dialAndStore installs a fresh connection for key, unless another goroutine
// won the race to create one first - sendOverTunnel can now run on several
// goroutines at once (see retainForReplay), and dropping a duplicate on the
// floor would leak its socket.
func (t *Tunnel) dialAndStore(key netip.AddrPort) (*tunnelConn, error) {
	connection, err := createUDPChannel(key)
	if err != nil {
		return nil, err
	}

	t.connectionBufferLock.Lock()
	defer t.connectionBufferLock.Unlock()
	if existing, exist := t.connectionBuffer[key]; exist {
		_ = connection.Close()
		return existing, nil
	}
	tc := newTunnelConn(connection, key)
	t.connectionBuffer[key] = tc
	return tc, nil
}

// newTunnelConn wraps a freshly dialled peer connection with the batched
// writer its address family needs. Unlike the listen socket - always
// dual-stack, see udpTunnelSocket - a socket net.DialUDP dials to one
// specific remote address is single-family, and dst.Addr() is never a
// v4-mapped v6 address here (see TableEntryCache.AddrFromIP's Unmap), so
// checking Is4() reliably tells the two apart. A node can have peers of both
// kinds at once, which is why this is decided per connection rather than
// once for the whole Tunnel.
func newTunnelConn(conn *net.UDPConn, dst netip.AddrPort) *tunnelConn {
	var bw batchWriter
	if dst.Addr().Is4() {
		bw = ipv4.NewPacketConn(conn)
	} else {
		bw = ipv6.NewPacketConn(conn)
	}
	tc := &tunnelConn{conn: conn, batch: bw}
	tc.lastUsed.Store(coarseClock.Load())
	return tc
}

// startConnectionEviction closes tunnel sockets that have gone unused, so the
// descriptor and socket-buffer cost of talking to a node once doesn't persist
// for the lifetime of the process.
func (t *Tunnel) startConnectionEviction() {
	ticker := time.NewTicker(connectionSweepInterval)
	go func() {
		for range ticker.C {
			t.evictIdleConnections(connectionIdleTimeout)
		}
	}()
}

func (t *Tunnel) evictIdleConnections(timeout time.Duration) {
	cutoff := coarseClock.Load() - int64(timeout.Seconds())

	// Collect first, then close outside the lock: Close can block, and the
	// datapath needs this map back.
	var idle []*tunnelConn
	t.connectionBufferLock.Lock()
	for key, con := range t.connectionBuffer {
		if con.lastUsed.Load() > cutoff {
			continue
		}
		// Identity check, as in sendOverTunnel's error path: only remove the
		// connection actually observed as idle, never a replacement that has
		// since been dialled for the same peer.
		if t.connectionBuffer[key] == con {
			delete(t.connectionBuffer, key)
			idle = append(idle, con)
		}
	}
	t.connectionBufferLock.Unlock()

	for _, con := range idle {
		_ = con.conn.Close()
	}
}

func createUDPChannel(raddr netip.AddrPort) (*net.UDPConn, error) {
	connection, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(raddr))
	if nil != err {
		logger.ErrorLogger().Println("Unable to connect to remote addr:", err)
		return nil, err
	}
	err = connection.SetWriteBuffer(socketBufferSize)
	if nil != err {
		// Not fatal: the socket still works with whatever the kernel's
		// default/clamped size is, just more prone to drops under bursts.
		logger.ErrorLogger().Println("Unable to grow UDP write buffer:", err)
	}
	return connection, nil
}

// GetName returns the name of the tun interface
func (t *Tunnel) GetName() string {
	return t.HostTUNDeviceName
}

// GetErrCh returns the error channel
// this channel sends all the errors of the tun device
func (t *Tunnel) GetErrCh() <-chan error {
	return t.errorChannel
}

// GetStopCh returns the errCh
// this channel is used to stop the service. After a shutdown the TUN device stops listening
func (t *Tunnel) GetStopCh() chan<- bool {
	return t.stopChannel
}

// GetFinishCh returns the confirmation that the channel stopped listening for packets
func (t *Tunnel) GetFinishCh() <-chan bool {
	return t.finishChannel
}
