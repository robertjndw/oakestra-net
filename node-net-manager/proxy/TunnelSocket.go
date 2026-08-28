package proxy

import (
	"net"
	"net/netip"

	"golang.org/x/net/ipv6"
)

// TunnelSocket abstracts the tunnel's listen socket: batched reads off it
// (recvmmsg, where the kernel supports it) and destination-addressed writes
// to a peer. dst is a parameter of WriteBatch - unlike TunDevice, which has
// none - because unlike the TUN end, every tunnel write has one specific
// peer; the TUN end has no destination to speak of.
type TunnelSocket interface {
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
	WriteBatch(dst netip.AddrPort, bufs [][]byte) (int, error)
	Close() error
}

// udpTunnelSocket backs TunnelSocket with the process's single UDP listen
// socket.
//
// net.ListenUDP("udp", ...) - the network this package has always used, see
// createTun - binds a dual-stack AF_INET6 socket on both Linux and Darwin: a
// bare port with no host resolves to the unspecified address, and "udp"
// (rather than "udp4"/"udp6") leaves IPV6_V6ONLY off, so v4 peers arrive as
// v4-mapped v6 addresses on the same socket. That is why this wraps the
// listen connection in ipv6.NewPacketConn, not ipv4's - ipv4.NewPacketConn
// would only ever see the v6-mapped peers, never the v4 ones directly, and
// in practice fails to read from a v6 socket at all. See
// TestUDPTunnelSocketDualStackReceive for the proof: it sends over both
// IPv4 and IPv6 loopback and asserts both are received through this type.
type udpTunnelSocket struct {
	conn *net.UDPConn
	pc   *ipv6.PacketConn
	// msgs is reused across ReadBatch calls - this socket has a single
	// reader (see ingoingLoop) - so batching doesn't cost an allocation per
	// call. It grows to fit the largest bufs any caller has passed so far.
	msgs []ipv6.Message
}

func newUDPTunnelSocket(conn *net.UDPConn) *udpTunnelSocket {
	return &udpTunnelSocket{conn: conn, pc: ipv6.NewPacketConn(conn)}
}

func (s *udpTunnelSocket) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	if len(s.msgs) < len(bufs) {
		msgs := make([]ipv6.Message, len(bufs))
		for i := range msgs {
			msgs[i].Buffers = make([][]byte, 1)
		}
		s.msgs = msgs
	}
	msgs := s.msgs[:len(bufs)]
	for i, b := range bufs {
		msgs[i].Buffers[0] = b
	}

	n, err := s.pc.ReadBatch(msgs, 0)
	if err != nil {
		return 0, err
	}
	for i := 0; i < n; i++ {
		sizes[i] = msgs[i].N
	}
	return n, nil
}

// WriteBatch loops over single writes. This socket is not where outgoing
// batching happens - every send here would need its own destination address
// regardless of grouping, and the actual per-peer traffic goes out over
// connectionBuffer's dialled connections instead (see
// Tunnel.sendOverTunnelBatch and tunnelConn.batch); this only has to be
// correct.
func (s *udpTunnelSocket) WriteBatch(dst netip.AddrPort, bufs [][]byte) (int, error) {
	addr := net.UDPAddrFromAddrPort(dst)
	for i, b := range bufs {
		if _, err := s.conn.WriteToUDP(b, addr); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (s *udpTunnelSocket) Close() error {
	return s.conn.Close()
}
