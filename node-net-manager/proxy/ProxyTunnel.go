package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/env"
	"NetManager/logger"
	"NetManager/proxy/iputils"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/songgao/water"
)

// packetReadBufferSize is how much is read per packet off the TUN device or
// UDP socket - generous headroom over any realistic MTU, but deliberately
// NOT the same constant as socketBufferSize below: that one sizes the
// kernel's socket buffer, and reusing it here would size every pooled
// per-packet buffer at multiple megabytes for no benefit.
const packetReadBufferSize = 64 * 1024

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

// tunnelConn is one UDP socket to a peer node, plus the coarse timestamp the
// idle sweeper uses to decide when to close it.
type tunnelConn struct {
	conn     *net.UDPConn
	lastUsed atomic.Int64
}

type GoProxyTunnel struct {
	environment       env.EnvironmentManager
	listenConnection  *net.UDPConn
	connectionBuffer  map[netip.AddrPort]*tunnelConn
	ifce              *water.Interface
	finishChannel     chan bool
	errorChannel      chan error
	stopChannel       chan bool
	HostTUNDeviceName string
	tunNetIPv6        string
	tunNetIP          string
	mtusize           string
	// The proxy subnetworks are netip.Prefix rather than net.IPNet so the
	// per-packet containment check needs no conversion of the parsed address.
	ProxyIPv4Prefix netip.Prefix
	ProxyIPv6Prefix netip.Prefix
	localIP         netip.Addr
	proxycache      *ProxyCache
	TunnelPort      int
	// connectionBufferLock guards only connectionBuffer. net.UDPConn is
	// itself safe for concurrent use, so nothing else needs to hold this
	// while a packet is actually being written.
	connectionBufferLock sync.RWMutex
	// replayLock guards replays and replayBytes. Both are only touched on a
	// cold miss, never on the steady-state packet path.
	replayLock  sync.Mutex
	replays     map[netip.Addr]*pendingReplay
	replayBytes int
	isListening bool
}

// packetBufPool holds MTU-sized buffers for reading packets off the TUN
// device and the UDP socket, so the read loops don't allocate one per
// packet. Buffers are always pooled at full capacity and resliced by the
// caller after a read.
var packetBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, packetReadBufferSize)
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

// handleOutgoing processes one packet read from the TUN device: translate it
// (if it targets the semantic-routing subnetwork) and forward it on. buf is
// only used for the duration of this call, unless it ends up retained for
// replay (see retainForReplay). mayRetain must be false when called from a
// replay goroutine itself - otherwise a resolution that succeeds but still
// yields no matching table entry would re-enter and replay forever.
func (proxy *GoProxyTunnel) handleOutgoing(buf []byte, mayRetain bool) {
	pkt, ok := iputils.Parse(buf)
	if !ok {
		return
	}
	if logger.IsDebug() {
		logger.DebugLogger().Printf("Outgoing packet:\t\t\t%s ---> %s\n", pkt.SrcIP(), pkt.DstIP())
	}

	// A later fragment has no transport header to resolve a flow with, only
	// the translation its first fragment already established. If that first
	// fragment is itself still queued waiting for the route, this one has to
	// wait behind it rather than be dropped - otherwise the datagram loses
	// every fragment but the first and can never reassemble.
	if isLaterFragment(&pkt) {
		if !proxy.forwardLaterFragment(&pkt) && mayRetain {
			proxy.retainFragmentForReplay(buf, pkt.DstIP())
		}
		return
	}
	if !pkt.HasTransport() {
		return
	}

	// The fragment key has to be taken before outgoingProxy rewrites the
	// addresses, so it matches the later fragments, which arrive untranslated.
	var fragKey fragmentKey
	firstFragment := pkt.IsFragment()
	if firstFragment {
		fragKey = keyFor(&pkt)
	}

	dstHost, dstPort, resolving, ok := proxy.outgoingProxy(&pkt)
	if !ok {
		if mayRetain && resolving != nil {
			proxy.retainForReplay(buf, pkt.DstIP(), resolving)
		}
		return
	}

	if firstFragment {
		proxy.proxycache.frags.remember(fragKey, fragmentTranslation{
			newSrc:      pkt.SrcIP(),
			newDst:      pkt.DstIP(),
			dstNode:     dstHost,
			dstNodePort: dstPort,
		})
	}
	proxy.forward(dstHost, dstPort, pkt.Bytes(), 0)
}

// forwardLaterFragment translates a non-first fragment using the state its
// first fragment left behind and sends it to the same node. Only the
// addresses (and, for IPv4, the header checksum) are rewritten - there is no
// transport header here to checksum, and Rewrite already knows not to look
// for one. Reports false when there is no such state, so the caller can
// decide whether the fragment is worth holding onto.
func (proxy *GoProxyTunnel) forwardLaterFragment(pkt *iputils.Packet) bool {
	translation, ok := proxy.proxycache.frags.lookup(keyFor(pkt))
	if !ok {
		return false
	}
	if !pkt.Rewrite(translation.newSrc, translation.newDst) {
		return false
	}
	proxy.forward(translation.dstNode, translation.dstNodePort, pkt.Bytes(), 0)
	return true
}

// isLaterFragment reports whether pkt is a fragment carrying no transport
// header. Non-TCP/UDP protocols are excluded: this proxy only ever translates
// those two, so fragment state is never kept for anything else.
func isLaterFragment(pkt *iputils.Packet) bool {
	if !pkt.IsFragment() || pkt.IsFirstFragment() {
		return false
	}
	return pkt.Protocol() == iputils.ProtoTCP || pkt.Protocol() == iputils.ProtoUDP
}

// maxReplayPacketsPerVIP bounds how many packets may queue behind one
// unresolved Service IP, and maxReplayBytes bounds the total across all of
// them. The old scheme kept a 64KiB pooled buffer per retained packet, so a
// full queue pinned 16MiB to hold packets of around the 1450-byte MTU.
const (
	maxReplayPacketsPerVIP = 32
	maxReplayBytes         = 1 << 20
)

// pendingReplay is the FIFO of packets waiting on one Service IP's resolution.
// Guarded by GoProxyTunnel.replayLock.
type pendingReplay struct {
	packets [][]byte
	bytes   int
}

// retainForReplay holds a copy of a packet whose ServiceIP is still being
// resolved and re-runs it once resolution finishes. Resolution can't happen on
// the packet path, so without this the first packet of every cold flow is
// lost: harmless for TCP, which retransmits, but it silently drops a one-shot
// UDP datagram whose only fault was arriving before its route.
//
// Packets queue per Service IP and replay in arrival order. Giving each
// retained packet its own goroutine instead - all of them blocked on the same
// resolution channel - hands the order they resume in to the scheduler, which
// reorders datagrams an application submitted in sequence.
func (proxy *GoProxyTunnel) retainForReplay(buf []byte, vip netip.Addr, resolving <-chan struct{}) {
	proxy.replayLock.Lock()

	if queue, waiting := proxy.replays[vip]; waiting {
		proxy.enqueueReplayLocked(queue, buf)
		proxy.replayLock.Unlock()
		return
	}

	queue := &pendingReplay{}
	if !proxy.enqueueReplayLocked(queue, buf) {
		proxy.replayLock.Unlock()
		return
	}
	if proxy.replays == nil {
		proxy.replays = make(map[netip.Addr]*pendingReplay)
	}
	proxy.replays[vip] = queue
	proxy.replayLock.Unlock()

	// Exactly one waiter per Service IP, started when its queue is created.
	go proxy.replayWhenResolved(vip, resolving)
}

// retainFragmentForReplay queues a later fragment behind the first fragment of
// its own datagram, which is already waiting for this Service IP to resolve.
// A later fragment is still addressed to the untranslated Service IP, so it
// keys into the same queue, and replay is FIFO - the first fragment installs
// the translation before these reach forwardLaterFragment again.
//
// It only ever appends to a queue that already exists. A later fragment
// carries no transport ports, so it cannot drive a resolution of its own, and
// with nothing already waiting there is no first fragment for it to stay
// consistent with - buffering it speculatively would mean holding
// attacker-controllable bytes for a first fragment that may never come.
//
// That is not a gap in normal operation: outgoingLoop is the only reader of
// the TUN device and processes packets one at a time, so the local kernel's
// own fragments reach handleOutgoing in the order it emitted them. The one
// interleaving that does occur is with a replay in progress, and
// replayWhenResolved keeps its queue published for exactly that reason.
func (proxy *GoProxyTunnel) retainFragmentForReplay(buf []byte, vip netip.Addr) {
	proxy.replayLock.Lock()
	defer proxy.replayLock.Unlock()

	if queue, waiting := proxy.replays[vip]; waiting {
		proxy.enqueueReplayLocked(queue, buf)
	}
}

// enqueueReplayLocked copies buf onto queue unless the per-Service-IP packet
// cap or the global byte budget is already reached. buf belongs to
// outgoingLoop's pool and is reused as soon as handleOutgoing returns, so it
// must be copied before being held past that call; the copy is sized to the
// packet, not to the pool's buffer.
//
// Drop-newest: a full queue means the application is already ahead of
// resolution, and evicting the head would reorder what does get through.
// Caller must hold replayLock.
func (proxy *GoProxyTunnel) enqueueReplayLocked(queue *pendingReplay, buf []byte) bool {
	if len(queue.packets) >= maxReplayPacketsPerVIP {
		return false
	}
	if proxy.replayBytes+len(buf) > maxReplayBytes {
		return false
	}
	queue.packets = append(queue.packets, append([]byte(nil), buf...))
	queue.bytes += len(buf)
	proxy.replayBytes += len(buf)
	return true
}

// replayWhenResolved waits for one Service IP's resolution attempt to finish
// and then re-runs everything queued behind it, in order. A failed attempt
// needs no special case: the replays miss the table again and are dropped,
// because they are not allowed to re-queue themselves.
func (proxy *GoProxyTunnel) replayWhenResolved(vip netip.Addr, resolving <-chan struct{}) {
	<-resolving

	// Drain in rounds, leaving the queue published until it is actually
	// empty. outgoingLoop keeps reading the TUN while this runs, so a later
	// fragment of a datagram being replayed right now can still arrive; if the
	// queue were detached up front it would find neither a queue to join nor
	// the translation state its first fragment is about to install, and be
	// dropped microseconds before it would have worked.
	//
	// This terminates: once resolution has finished, handleOutgoing only
	// retains a packet while GetTableEntryByServiceIP reports a resolution
	// still in flight. After success the route is in the table, and after
	// failure the negative cache is armed before this channel closes - so
	// nothing new joins the queue and the next round finds it empty.
	for {
		proxy.replayLock.Lock()
		queue := proxy.replays[vip]
		if queue == nil || len(queue.packets) == 0 {
			delete(proxy.replays, vip)
			if queue != nil {
				proxy.replayBytes -= queue.bytes
			}
			proxy.replayLock.Unlock()
			return
		}
		packets := queue.packets
		proxy.replayBytes -= queue.bytes
		queue.packets, queue.bytes = nil, 0
		proxy.replayLock.Unlock()

		for _, packet := range packets {
			proxy.handleOutgoing(packet, false)
		}
	}
}

// handleIngoing processes one packet received on the tunnel UDP socket (or
// forwarded locally, see forward()): reverse-translate it if it matches an
// outstanding flow, then write it to the TUN device. buf is only used for
// the duration of this call.
func (proxy *GoProxyTunnel) handleIngoing(buf []byte) {
	pkt, ok := iputils.Parse(buf)
	if !ok {
		return
	}
	if logger.IsDebug() {
		logger.DebugLogger().Printf("Ingoing packet:\t\t\t %s <--- %s\n", pkt.DstIP(), pkt.SrcIP())
	}

	if isLaterFragment(&pkt) {
		// Unlike the outgoing direction, an unknown fragment is still written
		// to the TUN device: an ingoing packet with no reverse mapping is
		// forwarded unchanged here, and a fragment is no different. That is
		// the common case on this path - ingoingProxy only matches flows this
		// node originated, so every inbound *request* is unmatched.
		//
		// Known limitation: if the two tunnel datagrams reorder and a later
		// fragment arrives before a first fragment that does get
		// reverse-translated, the two are written with different sources and
		// the datagram will not reassemble. Holding unknown later fragments
		// to cover that would penalise the far more common pass-through case.
		if translation, known := proxy.proxycache.frags.lookup(keyFor(&pkt)); known {
			pkt.Rewrite(translation.newSrc, translation.newDst)
		}
	} else {
		if !pkt.HasTransport() {
			return
		}

		var fragKey fragmentKey
		firstFragment := pkt.IsFragment()
		if firstFragment {
			fragKey = keyFor(&pkt)
		}

		// ingoingProxy returning false just means there's no reverse mapping
		// for this flow - the packet is still forwarded to the TUN device
		// unchanged.
		if proxy.ingoingProxy(&pkt) && firstFragment {
			proxy.proxycache.frags.remember(fragKey, fragmentTranslation{
				newSrc: pkt.SrcIP(),
				newDst: pkt.DstIP(),
			})
		}
	}

	if _, err := proxy.ifce.Write(pkt.Bytes()); err != nil {
		logger.ErrorLogger().Println(err)
	}
}

// outgoingProxy rewrites pkt in place if its destination falls in the
// semantic-routing subnetwork, resolving the target instance via the
// translation table (proxy.environment) and the per-flow ProxyCache. ok is
// false if the packet isn't part of the proxy subnetwork, or its ServiceIP
// can't currently be resolved - either way it should be dropped. resolving is
// non-nil only when the ServiceIP is still being resolved in the background
// (a cold miss), so the caller can hold onto the packet and retry once it
// closes instead of losing it outright.
func (proxy *GoProxyTunnel) outgoingProxy(pkt *iputils.Packet) (dstHost netip.Addr, dstPort int, resolving <-chan struct{}, ok bool) {
	dstIP := pkt.DstIP()
	srcIP := pkt.SrcIP()
	protocol := pkt.Protocol()
	srcport := int(pkt.SrcPort())
	dstport := int(pkt.DstPort())

	var inProxySubnet bool
	if pkt.Version() == 4 {
		inProxySubnet = proxy.ProxyIPv4Prefix.Contains(dstIP)
	} else {
		inProxySubnet = proxy.ProxyIPv6Prefix.Contains(dstIP)
	}
	if !inProxySubnet {
		return netip.Addr{}, 0, nil, false
	}

	// Check if the ServiceIP is known
	lookup := proxy.environment.GetTableEntryByServiceIP(dstIP)
	if len(lookup.Entries) < 1 {
		return netip.Addr{}, 0, lookup.Resolving, false
	}

	// Find the instanceIP of the current service
	instanceIP, ok := proxy.convertToInstanceIp(pkt.Version(), srcIP)
	if !ok {
		return netip.Addr{}, 0, nil, false
	}

	// Check proxy proxycache (if any active flow is there already)
	entry, exist := proxy.proxycache.RetrieveByServiceIP(protocol, srcIP, instanceIP, srcport, dstIP, dstport)
	usable := exist && entry.dstport >= 1
	if usable && entry.routeGen != lookup.Generation {
		// The table changed since this route was picked, so it has to be
		// checked against the current replica set once. While the generation
		// matches, that scan is skipped entirely.
		usable = TableEntryCache.IsRouteStillValid(entry.dstip, entry.dstNode, entry.dstNodePort, lookup.Entries)
		if usable {
			proxy.proxycache.MarkRouteCurrent(entry, lookup.Generation)
		}
	}

	if !usable {
		// Choose between the table entry according to the ServiceIP algorithm
		// TODO: so far this only uses RR, ServiceIP policies should be implemented here
		// rand.IntN (math/rand/v2) is safe to call concurrently and seeded
		// per-process, unlike a shared *rand.Rand - needed now that replay
		// goroutines (see retainForReplay) can call in here too.
		tableEntry := lookup.Entries[rand.IntN(len(lookup.Entries))]

		entryDstIPnet := tableEntry.Nsip
		if pkt.Version() == 6 {
			entryDstIPnet = tableEntry.Nsipv6
		}
		entryDstIP, ok := TableEntryCache.AddrFromIP(entryDstIPnet)
		if !ok {
			return netip.Addr{}, 0, nil, false
		}
		nodeAddr, ok := TableEntryCache.AddrFromIP(tableEntry.Nodeip)
		if !ok {
			return netip.Addr{}, 0, nil, false
		}

		// Update proxycache. dstNode/dstNodePort are cached here too - an
		// Nsip is only ever valid on the node that handed it out, so as long
		// as this cache entry (and its dstip) is still valid there's no need
		// to look Nodeip/Nodeport back up by Nsip on every packet.
		entry = ConversionEntry{
			srcip:         srcIP,
			dstip:         entryDstIP,
			dstServiceIp:  dstIP,
			srcInstanceIp: instanceIP,
			dstInstanceIp: instanceAddrOf(&tableEntry, pkt.Version()),
			srcport:       srcport,
			dstport:       dstport,
			protocol:      protocol,
			dstNode:       nodeAddr,
			dstNodePort:   tableEntry.Nodeport,
			routeGen:      lookup.Generation,
		}
		proxy.proxycache.Add(entry)
	}

	if !pkt.Rewrite(entry.srcInstanceIp, entry.dstip) {
		return netip.Addr{}, 0, nil, false
	}
	return entry.dstNode, entry.dstNodePort, nil, true
}

// instanceAddrOf returns the "instance IP" that uniquely identifies one
// deployed instance of a service, in the requested address family. It is the
// address that instance's own proxy will source its replies from.
func instanceAddrOf(entry *TableEntryCache.TableEntry, version uint8) netip.Addr {
	for _, sip := range entry.ServiceIP {
		if sip.IpType != TableEntryCache.InstanceNumber {
			continue
		}
		instanceIPnet := sip.Address
		if version == 6 {
			instanceIPnet = sip.Address_v6
		}
		addr, _ := TableEntryCache.AddrFromIP(instanceIPnet)
		return addr
	}
	return netip.Addr{}
}

// convertToInstanceIp resolves the stable "instance IP" that identifies
// srcIP's own service instance, for use as the translated source address.
func (proxy *GoProxyTunnel) convertToInstanceIp(version uint8, srcIP netip.Addr) (netip.Addr, bool) {
	instanceTableEntry, instanceexist := proxy.environment.GetTableEntryByNsIP(srcIP)
	if !instanceexist {
		logger.ErrorLogger().Println("Unable to find instance IP for service: ", srcIP)
		return netip.Addr{}, false
	}
	addr := instanceAddrOf(&instanceTableEntry, version)
	return addr, addr.IsValid()
}

// ingoingProxy checks the ProxyCache for a reverse mapping (a flow this node
// itself originated via outgoingProxy) and, if found, rewrites pkt in place
// back to its original semantic addressing. Returns false (no-op) if there
// is no such mapping - the packet is then forwarded unchanged.
func (proxy *GoProxyTunnel) ingoingProxy(pkt *iputils.Packet) bool {
	// The reply is addressed to the namespace IP and port the flow left from,
	// and sourced from the instance IP and port it was sent to.
	entry, exist := proxy.proxycache.RetrieveByInstanceIp(
		pkt.Protocol(), pkt.DstIP(), int(pkt.DstPort()), pkt.SrcIP(), int(pkt.SrcPort()))
	if !exist {
		return false
	}

	// Reverse conversion
	return pkt.Rewrite(entry.dstServiceIp, entry.srcip)
}

// Enable listening to outgoing packets
// if the goroutine must be stopped, send true to the stop channel
// when the channels finish listening a "true" is sent back to the finish channel
// in case of fatal error they are routed back to the err channel
func (proxy *GoProxyTunnel) tunOutgoingListen() {
	readerror := make(chan error)

	// async reader+processor
	go proxy.outgoingLoop(readerror)

	proxy.isListening = true
	logger.InfoLogger().Println("GoProxyTunnel outgoing listening started")
	for {
		select {
		case stopmsg := <-proxy.stopChannel:
			if stopmsg {
				logger.DebugLogger().Println("Outgoing listener received stop message")
				proxy.isListening = false
				proxy.finishChannel <- true
				return
			}
		case errormsg := <-readerror:
			proxy.errorChannel <- errormsg
		}
	}
}

// Enable listening for ingoing packets
// if the goroutine must be stopped, send true to the stop channel
// when the channels finish listening a "true" is sent back to the finish channel
// in case of fatal error they are routed back to the err channel
func (proxy *GoProxyTunnel) tunIngoingListen() {
	readerror := make(chan error)

	// async reader+processor
	go proxy.ingoingLoop(readerror)

	proxy.isListening = true
	logger.InfoLogger().Println("GoProxyTunnel ingoing listening started")
	for {
		select {
		case stopmsg := <-proxy.stopChannel:
			if stopmsg {
				logger.DebugLogger().Println("Ingoing listener received stop message")
				_ = proxy.listenConnection.Close()
				proxy.isListening = false
				proxy.finishChannel <- true
				return
			}
		case errormsg := <-readerror:
			proxy.errorChannel <- errormsg
		}
	}
}

// outgoingLoop reads packets from the TUN device and processes them
// synchronously, one at a time, reusing a pooled buffer for each read.
func (proxy *GoProxyTunnel) outgoingLoop(errchannel chan<- error) {
	for {
		buf := getPacketBuf()
		n, err := proxy.ifce.Read(*buf)
		if err != nil {
			putPacketBuf(buf)
			errchannel <- err
			continue
		}
		proxy.handleOutgoing((*buf)[:n], true)
		putPacketBuf(buf)
	}
}

// ingoingLoop reads packets from the tunnel UDP socket and processes them
// synchronously, one at a time, reusing a pooled buffer for each read.
func (proxy *GoProxyTunnel) ingoingLoop(errchannel chan<- error) {
	for {
		buf := getPacketBuf()
		n, _, err := proxy.listenConnection.ReadFromUDP(*buf)
		if err != nil {
			putPacketBuf(buf)
			errchannel <- err
			continue
		}
		proxy.handleIngoing((*buf)[:n])
		putPacketBuf(buf)
	}
}

// forward sends packetBytes to dstHost:dstPort over the tunnel, or - if the
// destination is this machine - hands it straight to the ingoing pipeline
// without going over the network at all.
func (proxy *GoProxyTunnel) forward(dstHost netip.Addr, dstPort int, packetBytes []byte, attemptNumber int) {
	if attemptNumber > 10 {
		return
	}

	// If destination host is this machine, forward packet directly to the ingoing traffic method
	if dstHost == proxy.localIP {
		if logger.IsDebug() {
			logger.DebugLogger().Println("Packet forwarded locally")
		}
		proxy.handleIngoing(packetBytes)
		return
	}

	if !dstHost.IsValid() {
		logger.ErrorLogger().Println("Invalid destination host:", dstHost)
		return
	}
	key := netip.AddrPortFrom(dstHost, uint16(dstPort))

	proxy.connectionBufferLock.RLock()
	con, exist := proxy.connectionBuffer[key]
	proxy.connectionBufferLock.RUnlock()

	if !exist {
		var err error
		con, err = proxy.dialAndStore(key)
		if err != nil {
			return
		}
	}

	con.lastUsed.Store(coarseClock.Load())

	// net.UDPConn is safe for concurrent use - no lock needed around the
	// write itself, only around the map lookup above.
	_, err := con.conn.Write(packetBytes)
	if err != nil {
		_ = con.conn.Close()
		logger.ErrorLogger().Println(err)

		// con is confirmed dead - evict it so dialAndStore's double-check
		// doesn't just hand it straight back. Guard on identity: another
		// goroutine may have already replaced it with a live connection.
		proxy.connectionBufferLock.Lock()
		if proxy.connectionBuffer[key] == con {
			delete(proxy.connectionBuffer, key)
		}
		proxy.connectionBufferLock.Unlock()

		if _, err := proxy.dialAndStore(key); err != nil {
			return
		}
		// Try again
		proxy.forward(dstHost, dstPort, packetBytes, attemptNumber+1)
	}
}

// dialAndStore installs a fresh connection for key, unless another goroutine
// won the race to create one first - forward() can now run on several
// goroutines at once (see retainForReplay), and dropping a duplicate on the
// floor would leak its socket.
func (proxy *GoProxyTunnel) dialAndStore(key netip.AddrPort) (*tunnelConn, error) {
	connection, err := createUDPChannel(key)
	if err != nil {
		return nil, err
	}

	proxy.connectionBufferLock.Lock()
	defer proxy.connectionBufferLock.Unlock()
	if existing, exist := proxy.connectionBuffer[key]; exist {
		_ = connection.Close()
		return existing, nil
	}
	tc := &tunnelConn{conn: connection}
	tc.lastUsed.Store(coarseClock.Load())
	proxy.connectionBuffer[key] = tc
	return tc, nil
}

// startConnectionEviction closes tunnel sockets that have gone unused, so the
// descriptor and socket-buffer cost of talking to a node once doesn't persist
// for the lifetime of the process.
func (proxy *GoProxyTunnel) startConnectionEviction() {
	ticker := time.NewTicker(connectionSweepInterval)
	go func() {
		for range ticker.C {
			proxy.evictIdleConnections(connectionIdleTimeout)
		}
	}()
}

func (proxy *GoProxyTunnel) evictIdleConnections(timeout time.Duration) {
	cutoff := coarseClock.Load() - int64(timeout.Seconds())

	// Collect first, then close outside the lock: Close can block, and the
	// datapath needs this map back.
	var idle []*tunnelConn
	proxy.connectionBufferLock.Lock()
	for key, con := range proxy.connectionBuffer {
		if con.lastUsed.Load() > cutoff {
			continue
		}
		// Identity check, as in forward()'s error path: only remove the
		// connection actually observed as idle, never a replacement that has
		// since been dialled for the same peer.
		if proxy.connectionBuffer[key] == con {
			delete(proxy.connectionBuffer, key)
			idle = append(idle, con)
		}
	}
	proxy.connectionBufferLock.Unlock()

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
func (proxy *GoProxyTunnel) GetName() string {
	return proxy.HostTUNDeviceName
}

// GetErrCh returns the error channel
// this channel sends all the errors of the tun device
func (proxy *GoProxyTunnel) GetErrCh() <-chan error {
	return proxy.errorChannel
}

// GetStopCh returns the errCh
// this channel is used to stop the service. After a shutdown the TUN device stops listening
func (proxy *GoProxyTunnel) GetStopCh() chan<- bool {
	return proxy.stopChannel
}

// GetFinishCh returns the confirmation that the channel stopped listening for packets
func (proxy *GoProxyTunnel) GetFinishCh() <-chan bool {
	return proxy.finishChannel
}
