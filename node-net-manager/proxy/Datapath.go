package proxy

import (
	"NetManager/TableEntryCache"
	"NetManager/logger"
	"NetManager/proxy/iputils"
	"NetManager/resolver"
	"math/rand/v2"
	"net/netip"
	"sync"
)

// Direction says which side of the tunnel a packet was read from.
type Direction uint8

const (
	Outgoing Direction = iota // read off the TUN device
	Ingoing                   // read off the tunnel socket
)

// ActionKind says what the caller should do with the Action's Packet.
type ActionKind uint8

const (
	ActionDrop    ActionKind = iota
	ActionForward            // send over the tunnel to Dst
	ActionDeliver            // write to the TUN device
)

// Action is the datapath's verdict on one packet: what to do with it, and -
// for ActionForward - where to send it. Packet aliases the caller's buffer
// rather than copying it, so the caller must not reuse that buffer until the
// Action has been acted on.
type Action struct {
	Kind   ActionKind
	Dst    netip.AddrPort // ActionForward only
	Packet []byte
}

// Sink receives Actions produced off the synchronous path - today only from
// the replay goroutine (see replayWhenResolved).
type Sink interface {
	Emit(Action)
}

// Datapath decides what happens to a packet: translate it, queue it for
// replay, or drop it. It owns the flow cache, fragment state, replay queues,
// the resolver, the local IP and the proxy prefixes, and performs no socket
// or TUN I/O itself - that is Tunnel's job, driven by the Action this returns.
type Datapath struct {
	environment resolver.Resolver
	localIP     netip.Addr
	// The proxy subnetworks are netip.Prefix rather than net.IPNet so the
	// per-packet containment check needs no conversion of the parsed address.
	ProxyIPv4Prefix netip.Prefix
	ProxyIPv6Prefix netip.Prefix
	proxycache      *ProxyCache
	// out is where the replay goroutine (the only asynchronous producer of
	// Actions) sends what it decides. The synchronous path never uses it -
	// Handle returns its Action directly to the caller instead.
	out Sink
	// replayLock guards replays and replayBytes. Both are only touched on a
	// cold miss, never on the steady-state packet path.
	replayLock  sync.Mutex
	replays     map[netip.Addr]*pendingReplay
	replayBytes int
}

// NewDatapath builds a Datapath. out receives whatever the replay goroutine
// decides once a Service IP resolves - see Sink.
func NewDatapath(r resolver.Resolver, localIP netip.Addr, v4, v6 netip.Prefix, out Sink) *Datapath {
	return &Datapath{
		environment:     r,
		localIP:         localIP,
		ProxyIPv4Prefix: v4,
		ProxyIPv6Prefix: v6,
		proxycache:      NewProxyCache(),
		out:             out,
	}
}

// SetResolver replaces the resolver used to answer table lookups.
func (d *Datapath) SetResolver(r resolver.Resolver) {
	d.environment = r
}

// Handle decides what to do with one packet read from dir, returning the
// Action for the caller to perform. This is the entry point for both read
// loops, so the caller can batch the resulting I/O without a channel hop.
func (d *Datapath) Handle(dir Direction, buf []byte) Action {
	if dir == Outgoing {
		return d.handleOutgoing(buf, true)
	}
	return d.handleIngoing(buf)
}

// handleOutgoing decides what to do with one packet read from the TUN device:
// translate it (if it targets the semantic-routing subnetwork) and forward
// it on. buf is only used for the duration of this call, unless it ends up
// retained for replay (see retainForReplay). mayRetain must be false when
// called from a replay goroutine itself - otherwise a resolution that
// succeeds but still yields no matching table entry would re-enter and
// replay forever.
func (d *Datapath) handleOutgoing(buf []byte, mayRetain bool) Action {
	pkt, ok := iputils.Parse(buf)
	if !ok {
		return Action{Kind: ActionDrop}
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
		if action, ok := d.forwardLaterFragment(&pkt); ok {
			return action
		}
		if mayRetain {
			d.retainFragmentForReplay(buf, pkt.DstIP())
		}
		return Action{Kind: ActionDrop}
	}
	if !pkt.HasTransport() {
		return Action{Kind: ActionDrop}
	}

	// The fragment key has to be taken before outgoingProxy rewrites the
	// addresses, so it matches the later fragments, which arrive untranslated.
	var fragKey fragmentKey
	firstFragment := pkt.IsFragment()
	if firstFragment {
		fragKey = keyFor(&pkt)
	}

	dstHost, dstPort, resolving, ok := d.outgoingProxy(&pkt)
	if !ok {
		if mayRetain && resolving != nil {
			d.retainForReplay(buf, pkt.DstIP(), resolving)
		}
		return Action{Kind: ActionDrop}
	}

	if firstFragment {
		d.proxycache.frags.remember(fragKey, fragmentTranslation{
			newSrc:      pkt.SrcIP(),
			newDst:      pkt.DstIP(),
			dstNode:     dstHost,
			dstNodePort: dstPort,
		})
	}
	return d.forwardResult(dstHost, dstPort, pkt.Bytes())
}

// forwardResult turns a resolved destination into the Action the caller
// should take: if the destination is this machine, the packet never has to
// leave - hand it straight to the ingoing pipeline and return whatever that
// decides, instead of round-tripping it over the network. dstHost is always
// valid here - both callers (outgoingProxy's route resolution and its cached
// path) only ever hand back an address that already passed
// TableEntryCache.AddrFromIP's validity check.
func (d *Datapath) forwardResult(dstHost netip.Addr, dstPort int, packetBytes []byte) Action {
	if dstHost == d.localIP {
		if logger.IsDebug() {
			logger.DebugLogger().Println("Packet forwarded locally")
		}
		return d.handleIngoing(packetBytes)
	}

	return Action{
		Kind:   ActionForward,
		Dst:    netip.AddrPortFrom(dstHost, uint16(dstPort)),
		Packet: packetBytes,
	}
}

// forwardLaterFragment translates a non-first fragment using the state its
// first fragment left behind and reports where to send it, to the same node
// its first fragment went to. Only the addresses (and, for IPv4, the header
// checksum) are rewritten - there is no transport header here to checksum,
// and Rewrite already knows not to look for one. ok is false when there is no
// such state, so the caller can decide whether the fragment is worth holding
// onto.
func (d *Datapath) forwardLaterFragment(pkt *iputils.Packet) (action Action, ok bool) {
	translation, ok := d.proxycache.frags.lookup(keyFor(pkt))
	if !ok {
		return Action{}, false
	}
	if !pkt.Rewrite(translation.newSrc, translation.newDst) {
		return Action{}, false
	}
	return d.forwardResult(translation.dstNode, translation.dstNodePort, pkt.Bytes()), true
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
// Guarded by Datapath.replayLock.
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
func (d *Datapath) retainForReplay(buf []byte, vip netip.Addr, resolving <-chan struct{}) {
	d.replayLock.Lock()

	if queue, waiting := d.replays[vip]; waiting {
		d.enqueueReplayLocked(queue, buf)
		d.replayLock.Unlock()
		return
	}

	queue := &pendingReplay{}
	if !d.enqueueReplayLocked(queue, buf) {
		d.replayLock.Unlock()
		return
	}
	if d.replays == nil {
		d.replays = make(map[netip.Addr]*pendingReplay)
	}
	d.replays[vip] = queue
	d.replayLock.Unlock()

	// Exactly one waiter per Service IP, started when its queue is created.
	go d.replayWhenResolved(vip, resolving)
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
func (d *Datapath) retainFragmentForReplay(buf []byte, vip netip.Addr) {
	d.replayLock.Lock()
	defer d.replayLock.Unlock()

	if queue, waiting := d.replays[vip]; waiting {
		d.enqueueReplayLocked(queue, buf)
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
func (d *Datapath) enqueueReplayLocked(queue *pendingReplay, buf []byte) bool {
	if len(queue.packets) >= maxReplayPacketsPerVIP {
		return false
	}
	if d.replayBytes+len(buf) > maxReplayBytes {
		return false
	}
	queue.packets = append(queue.packets, append([]byte(nil), buf...))
	queue.bytes += len(buf)
	d.replayBytes += len(buf)
	return true
}

// replayWhenResolved waits for one Service IP's resolution attempt to finish
// and then re-runs everything queued behind it, in order, emitting the result
// of each through out. A failed attempt needs no special case: the replays
// miss the table again and are dropped, because they are not allowed to
// re-queue themselves.
func (d *Datapath) replayWhenResolved(vip netip.Addr, resolving <-chan struct{}) {
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
		d.replayLock.Lock()
		queue := d.replays[vip]
		if queue == nil || len(queue.packets) == 0 {
			delete(d.replays, vip)
			if queue != nil {
				d.replayBytes -= queue.bytes
			}
			d.replayLock.Unlock()
			return
		}
		packets := queue.packets
		d.replayBytes -= queue.bytes
		queue.packets, queue.bytes = nil, 0
		d.replayLock.Unlock()

		for _, packet := range packets {
			d.out.Emit(d.handleOutgoing(packet, false))
		}
	}
}

// handleIngoing processes one packet received on the tunnel UDP socket (or
// forwarded locally, see forwardResult): reverse-translate it if it matches
// an outstanding flow, then hand it back to be written to the TUN device.
// buf is only used for the duration of this call.
func (d *Datapath) handleIngoing(buf []byte) Action {
	pkt, ok := iputils.Parse(buf)
	if !ok {
		return Action{Kind: ActionDrop}
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
		if translation, known := d.proxycache.frags.lookup(keyFor(&pkt)); known {
			pkt.Rewrite(translation.newSrc, translation.newDst)
		}
	} else {
		if !pkt.HasTransport() {
			return Action{Kind: ActionDrop}
		}

		var fragKey fragmentKey
		firstFragment := pkt.IsFragment()
		if firstFragment {
			fragKey = keyFor(&pkt)
		}

		// ingoingProxy returning false just means there's no reverse mapping
		// for this flow - the packet is still forwarded to the TUN device
		// unchanged.
		if d.ingoingProxy(&pkt) && firstFragment {
			d.proxycache.frags.remember(fragKey, fragmentTranslation{
				newSrc: pkt.SrcIP(),
				newDst: pkt.DstIP(),
			})
		}
	}

	return Action{Kind: ActionDeliver, Packet: pkt.Bytes()}
}

// outgoingProxy rewrites pkt in place if its destination falls in the
// semantic-routing subnetwork, resolving the target instance via the
// translation table (d.environment) and the per-flow ProxyCache. ok is
// false if the packet isn't part of the proxy subnetwork, or its ServiceIP
// can't currently be resolved - either way it should be dropped. resolving is
// non-nil only when the ServiceIP is still being resolved in the background
// (a cold miss), so the caller can hold onto the packet and retry once it
// closes instead of losing it outright.
func (d *Datapath) outgoingProxy(pkt *iputils.Packet) (dstHost netip.Addr, dstPort int, resolving <-chan struct{}, ok bool) {
	dstIP := pkt.DstIP()
	srcIP := pkt.SrcIP()
	protocol := pkt.Protocol()
	srcport := int(pkt.SrcPort())
	dstport := int(pkt.DstPort())

	var inProxySubnet bool
	if pkt.Version() == 4 {
		inProxySubnet = d.ProxyIPv4Prefix.Contains(dstIP)
	} else {
		inProxySubnet = d.ProxyIPv6Prefix.Contains(dstIP)
	}
	if !inProxySubnet {
		return netip.Addr{}, 0, nil, false
	}

	// Check if the ServiceIP is known
	lookup := d.environment.GetTableEntryByServiceIP(dstIP)
	if len(lookup.Entries) < 1 {
		return netip.Addr{}, 0, lookup.Resolving, false
	}

	// Find the instanceIP of the current service
	instanceIP, ok := d.convertToInstanceIp(pkt.Version(), srcIP)
	if !ok {
		return netip.Addr{}, 0, nil, false
	}

	key := FlowKey{
		Protocol:      protocol,
		SrcIP:         srcIP,
		SrcInstanceIP: instanceIP,
		DstServiceIP:  dstIP,
		SrcPort:       srcport,
		DstPort:       dstport,
	}

	// Check proxy proxycache (if any active flow is there already)
	route, usable := d.proxycache.Route(key, lookup)
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

		// dstNode/dstNodePort are cached here too - an Nsip is only ever
		// valid on the node that handed it out, so as long as this cache
		// entry (and its dstip) is still valid there's no need to look
		// Nodeip/Nodeport back up by Nsip on every packet.
		route = Route{
			SrcInstanceIP: instanceIP,
			DstIP:         entryDstIP,
			DstNode:       nodeAddr,
			DstNodePort:   tableEntry.Nodeport,
		}
		d.proxycache.Install(key, route, instanceAddrOf(&tableEntry, pkt.Version()), lookup.Generation)
	}

	if !pkt.Rewrite(route.SrcInstanceIP, route.DstIP) {
		return netip.Addr{}, 0, nil, false
	}
	return route.DstNode, route.DstNodePort, nil, true
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
func (d *Datapath) convertToInstanceIp(version uint8, srcIP netip.Addr) (netip.Addr, bool) {
	instanceTableEntry, instanceexist := d.environment.GetTableEntryByNsIP(srcIP)
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
func (d *Datapath) ingoingProxy(pkt *iputils.Packet) bool {
	// The reply is addressed to the namespace IP and port the flow left from,
	// and sourced from the instance IP and port it was sent to.
	r, exist := d.proxycache.Reverse(
		pkt.Protocol(), pkt.DstIP(), int(pkt.DstPort()), pkt.SrcIP(), int(pkt.SrcPort()))
	if !exist {
		return false
	}

	// Reverse conversion
	return pkt.Rewrite(r.DstServiceIP, r.SrcIP)
}
