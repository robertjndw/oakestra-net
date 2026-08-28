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

type GoProxyTunnel struct {
	environment         env.EnvironmentManager
	listenConnection    *net.UDPConn
	connectionBuffer    map[netip.AddrPort]*net.UDPConn
	ifce                *water.Interface
	finishChannel       chan bool
	errorChannel        chan error
	stopChannel         chan bool
	HostTUNDeviceName   string
	tunNetIPv6          string
	tunNetIP            string
	mtusize             string
	ProxyIpSubnetwork   net.IPNet
	ProxyIPv6Subnetwork net.IPNet
	localIP             net.IP
	proxycache          *ProxyCache
	TunnelPort          int
	// connectionBufferLock guards only connectionBuffer. net.UDPConn is
	// itself safe for concurrent use, so nothing else needs to hold this
	// while a packet is actually being written.
	connectionBufferLock sync.RWMutex
	isListening          bool
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
	if !ok || !pkt.HasTransport() {
		return
	}
	if logger.IsDebug() {
		logger.DebugLogger().Printf("Outgoing packet:\t\t\t%s ---> %s\n", pkt.SrcIP(), pkt.DstIP())
	}

	dstHost, dstPort, resolving, ok := proxy.outgoingProxy(&pkt)
	if !ok {
		if mayRetain && resolving != nil {
			proxy.retainForReplay(buf, resolving)
		}
		return
	}
	proxy.forward(dstHost, dstPort, pkt.Bytes(), 0)
}

// maxPendingReplayPackets bounds how many packets may be held at once waiting
// for their destination ServiceIP to resolve.
const maxPendingReplayPackets = 256

var pendingReplayCount atomic.Int32

// retainForReplay holds a copy of a packet whose ServiceIP is still being
// resolved and re-runs it once resolution finishes. Resolution can't happen on
// the packet path, so without this the first packet of every cold flow is
// lost: harmless for TCP, which retransmits, but it silently drops a one-shot
// UDP datagram whose only fault was arriving before its route.
func (proxy *GoProxyTunnel) retainForReplay(buf []byte, resolving <-chan struct{}) {
	if pendingReplayCount.Add(1) > maxPendingReplayPackets {
		pendingReplayCount.Add(-1)
		return
	}

	// buf belongs to outgoingLoop's pool and is reused as soon as
	// handleOutgoing returns, so it must be copied before we hang onto it
	// past this call.
	cp := getPacketBuf()
	*cp = (*cp)[:len(buf)]
	copy(*cp, buf)

	go func() {
		defer pendingReplayCount.Add(-1)
		defer putPacketBuf(cp)
		<-resolving
		proxy.handleOutgoing(*cp, false)
	}()
}

// handleIngoing processes one packet received on the tunnel UDP socket (or
// forwarded locally, see forward()): reverse-translate it if it matches an
// outstanding flow, then write it to the TUN device. buf is only used for
// the duration of this call.
func (proxy *GoProxyTunnel) handleIngoing(buf []byte) {
	pkt, ok := iputils.Parse(buf)
	if !ok || !pkt.HasTransport() {
		return
	}
	if logger.IsDebug() {
		logger.DebugLogger().Printf("Ingoing packet:\t\t\t %s <--- %s\n", pkt.DstIP(), pkt.SrcIP())
	}

	// ingoingProxy returning false just means there's no reverse mapping for
	// this flow - the packet is still forwarded to the TUN device unchanged.
	proxy.ingoingProxy(&pkt)

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
func (proxy *GoProxyTunnel) outgoingProxy(pkt *iputils.Packet) (dstHost net.IP, dstPort int, resolving <-chan struct{}, ok bool) {
	dstIP := pkt.DstIP()
	srcIP := pkt.SrcIP()
	srcport := int(pkt.SrcPort())
	dstport := int(pkt.DstPort())

	dstIPNet := netIPFromAddr(dstIP)
	var inProxySubnet bool
	if pkt.Version() == 4 {
		inProxySubnet = proxy.ProxyIpSubnetwork.Contains(dstIPNet)
	} else {
		inProxySubnet = proxy.ProxyIPv6Subnetwork.Contains(dstIPNet)
	}
	if !inProxySubnet {
		return nil, 0, nil, false
	}

	// Check if the ServiceIP is known
	tableEntryList, resolveCh := proxy.environment.GetTableEntryByServiceIP(dstIPNet)
	if len(tableEntryList) < 1 {
		return nil, 0, resolveCh, false
	}

	// Find the instanceIP of the current service
	instanceIP, ok := proxy.convertToInstanceIp(pkt.Version(), srcIP)
	if !ok {
		return nil, 0, nil, false
	}

	// Check proxy proxycache (if any active flow is there already)
	entry, exist := proxy.proxycache.RetrieveByServiceIP(srcIP, instanceIP, srcport, dstIP, dstport)

	if !exist || entry.dstport < 1 || !TableEntryCache.IsRouteStillValid(entry.dstip, entry.dstNode, entry.dstNodePort, tableEntryList) {
		// Choose between the table entry according to the ServiceIP algorithm
		// TODO: so far this only uses RR, ServiceIP policies should be implemented here
		// rand.IntN (math/rand/v2) is safe to call concurrently and seeded
		// per-process, unlike a shared *rand.Rand - needed now that replay
		// goroutines (see retainForReplay) can call in here too.
		tableEntry := tableEntryList[rand.IntN(len(tableEntryList))]

		entryDstIPnet := tableEntry.Nsip
		if pkt.Version() == 6 {
			entryDstIPnet = tableEntry.Nsipv6
		}
		entryDstIP, ok := TableEntryCache.AddrFromIP(entryDstIPnet)
		if !ok {
			return nil, 0, nil, false
		}
		nodeAddr, ok := TableEntryCache.AddrFromIP(tableEntry.Nodeip)
		if !ok {
			return nil, 0, nil, false
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
			srcport:       srcport,
			dstport:       dstport,
			dstNode:       nodeAddr,
			dstNodePort:   tableEntry.Nodeport,
		}
		proxy.proxycache.Add(entry)
	}

	if !pkt.Rewrite(entry.srcInstanceIp, entry.dstip) {
		return nil, 0, nil, false
	}
	return netIPFromAddr(entry.dstNode), entry.dstNodePort, nil, true
}

// convertToInstanceIp resolves the stable "instance IP" that identifies
// srcIP's own service instance, for use as the translated source address.
func (proxy *GoProxyTunnel) convertToInstanceIp(version uint8, srcIP netip.Addr) (netip.Addr, bool) {
	instanceTableEntry, instanceexist := proxy.environment.GetTableEntryByNsIP(netIPFromAddr(srcIP))
	if !instanceexist {
		logger.ErrorLogger().Println("Unable to find instance IP for service: ", srcIP)
		return netip.Addr{}, false
	}
	for _, sip := range instanceTableEntry.ServiceIP {
		if sip.IpType != TableEntryCache.InstanceNumber {
			continue
		}
		instanceIPnet := sip.Address
		if version == 6 {
			instanceIPnet = sip.Address_v6
		}
		return TableEntryCache.AddrFromIP(instanceIPnet)
	}
	return netip.Addr{}, false
}

// ingoingProxy checks the ProxyCache for a reverse mapping (a flow this node
// itself originated via outgoingProxy) and, if found, rewrites pkt in place
// back to its original semantic addressing. Returns false (no-op) if there
// is no such mapping - the packet is then forwarded unchanged.
func (proxy *GoProxyTunnel) ingoingProxy(pkt *iputils.Packet) bool {
	dstport := int(pkt.DstPort())
	srcport := int(pkt.SrcPort())

	// Check proxy proxycache for REVERSE entry conversion
	// DstIP -> srcip, DstPort->srcport, srcport -> dstport
	entry, exist := proxy.proxycache.RetrieveByInstanceIp(pkt.DstIP(), dstport, srcport)
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
func (proxy *GoProxyTunnel) forward(dstHost net.IP, dstPort int, packetBytes []byte, attemptNumber int) {
	if attemptNumber > 10 {
		return
	}

	// If destination host is this machine, forward packet directly to the ingoing traffic method
	if dstHost.Equal(proxy.localIP) {
		if logger.IsDebug() {
			logger.DebugLogger().Println("Packet forwarded locally")
		}
		proxy.handleIngoing(packetBytes)
		return
	}

	addr, ok := TableEntryCache.AddrFromIP(dstHost)
	if !ok {
		logger.ErrorLogger().Println("Invalid destination host:", dstHost)
		return
	}
	key := netip.AddrPortFrom(addr, uint16(dstPort))

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

	// net.UDPConn is safe for concurrent use - no lock needed around the
	// write itself, only around the map lookup above.
	_, err := con.Write(packetBytes)
	if err != nil {
		_ = con.Close()
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
func (proxy *GoProxyTunnel) dialAndStore(key netip.AddrPort) (*net.UDPConn, error) {
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
	proxy.connectionBuffer[key] = connection
	return connection, nil
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

// netIPFromAddr converts a netip.Addr to a net.IP in its 16-byte form, which
// net.IP.Equal/net.IPNet.Contains compare correctly regardless of whether
// the other side is a 4-byte or 16-byte representation of the same address.
func netIPFromAddr(addr netip.Addr) net.IP {
	if !addr.IsValid() {
		return nil
	}
	b := addr.As16()
	return net.IP(b[:])
}
