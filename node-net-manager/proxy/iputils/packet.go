// Package iputils provides a zero-copy, zero-allocation view over raw IPv4
// and IPv6 datagrams for the proxy's NAT-style translation: swapping the
// source and destination addresses in place and fixing up the affected
// checksums incrementally (RFC 1624), instead of parsing the packet into
// gopacket layer structs, rebuilding it in a fresh buffer, and re-parsing
// the result - which is what this package used to do.
//
// Only the source/destination addresses are ever rewritten; ports and
// payload are never touched, which is exactly the case RFC 1624's
// incremental checksum update is for for: it recomputes the checksum from
// the old/new header bytes alone, in O(1), without looking at the payload.
package iputils

import "net/netip"

// Protocol numbers this package understands. Anything else is passed through
// unparsed at the L4 level (HasTransport reports false).
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

const (
	ipv4HeaderMinLen = 20
	ipv6HeaderLen    = 40
	tcpHeaderMinLen  = 20
	udpHeaderLen     = 8
)

// Packet is a zero-copy view over a single raw IP datagram held in buf.
// Every method reads or mutates buf directly; Packet itself never allocates
// and never copies buf. The zero value is not valid - always obtain a
// Packet via Parse.
type Packet struct {
	buf      []byte
	version  uint8 // 4 or 6
	protocol uint8 // IPv4 protocol field / IPv6 next-header of the L4 payload
	ipLen    int   // IP header length in bytes (v4: IHL*4; v6: 40 + extension headers)
	l4Start  int   // offset of the L4 (TCP/UDP) header; -1 if none is present here
}

// Parse decodes buf just far enough to translate it: IP version, header
// length, protocol, and - for the first fragment or an unfragmented packet -
// the L4 header offset. It returns false if buf is too short or malformed
// to safely process. buf is retained, not copied: the caller must not reuse
// it while the returned Packet is in use.
func Parse(buf []byte) (Packet, bool) {
	if len(buf) < 1 {
		return Packet{}, false
	}
	switch buf[0] >> 4 {
	case 4:
		return parseIPv4(buf)
	case 6:
		return parseIPv6(buf)
	default:
		return Packet{}, false
	}
}

func parseIPv4(buf []byte) (Packet, bool) {
	if len(buf) < ipv4HeaderMinLen {
		return Packet{}, false
	}
	ihl := int(buf[0]&0x0f) * 4
	if ihl < ipv4HeaderMinLen || len(buf) < ihl {
		return Packet{}, false
	}

	p := Packet{
		buf:      buf,
		version:  4,
		protocol: buf[9],
		ipLen:    ihl,
		l4Start:  -1,
	}
	// Fragment Offset is the low 13 bits of the flags+offset field. Only the
	// first fragment (offset 0) carries an L4 header - later fragments are
	// raw payload continuation and must not be parsed as one.
	fragOffset := readUint16(buf[6:8]) & 0x1fff
	if fragOffset == 0 {
		p.l4Start = ihl
	}
	return p, true
}

func parseIPv6(buf []byte) (Packet, bool) {
	if len(buf) < ipv6HeaderLen {
		return Packet{}, false
	}

	nextHeader := buf[6]
	offset := ipv6HeaderLen
	isFragment := false
	firstFragment := true

	// Walk the extension header chain to find the L4 header. Bounded so a
	// malformed or adversarial chain can't spin forever.
walk:
	for range 8 {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options: length in 8-byte units
			if len(buf) < offset+2 {
				return Packet{}, false
			}
			nh, extLen := buf[offset], (int(buf[offset+1])+1)*8
			if len(buf) < offset+extLen {
				return Packet{}, false
			}
			nextHeader, offset = nh, offset+extLen
		case 51: // Authentication Header: length in 4-byte units, encoded as (len-2)
			if len(buf) < offset+2 {
				return Packet{}, false
			}
			nh, extLen := buf[offset], (int(buf[offset+1])+2)*4
			if len(buf) < offset+extLen {
				return Packet{}, false
			}
			nextHeader, offset = nh, offset+extLen
		case 44: // Fragment header, fixed 8 bytes
			if len(buf) < offset+8 {
				return Packet{}, false
			}
			isFragment = true
			// Fragment Offset is the top 13 bits of bytes offset+2:offset+4.
			firstFragment = readUint16(buf[offset+2:offset+4])>>3 == 0
			nextHeader, offset = buf[offset], offset+8
		default:
			break walk
		}
	}

	p := Packet{
		buf:      buf,
		version:  6,
		protocol: nextHeader,
		ipLen:    offset,
		l4Start:  -1,
	}
	if !isFragment || firstFragment {
		p.l4Start = offset
	}
	return p, true
}

// Version returns 4 or 6.
func (p Packet) Version() uint8 { return p.version }

// Protocol returns the IPv4 protocol field / IPv6 next-header value of the
// L4 payload (e.g. ProtoTCP, ProtoUDP).
func (p Packet) Protocol() uint8 { return p.protocol }

// HasTransport reports whether a TCP or UDP header is present at l4Start and
// fully within the buffer. False for non-TCP/UDP protocols and for
// non-first IP fragments, which carry no L4 header at all.
func (p Packet) HasTransport() bool {
	if p.l4Start < 0 {
		return false
	}
	switch p.protocol {
	case ProtoTCP:
		return len(p.buf) >= p.l4Start+tcpHeaderMinLen
	case ProtoUDP:
		return len(p.buf) >= p.l4Start+udpHeaderLen
	default:
		return false
	}
}

// SrcIP returns the packet's source address.
func (p Packet) SrcIP() netip.Addr {
	if p.version == 4 {
		return netip.AddrFrom4([4]byte(p.buf[12:16]))
	}
	return netip.AddrFrom16([16]byte(p.buf[8:24]))
}

// DstIP returns the packet's destination address.
func (p Packet) DstIP() netip.Addr {
	if p.version == 4 {
		return netip.AddrFrom4([4]byte(p.buf[16:20]))
	}
	return netip.AddrFrom16([16]byte(p.buf[24:40]))
}

// SrcPort returns the L4 source port. Only valid when HasTransport is true.
func (p Packet) SrcPort() uint16 {
	return readUint16(p.buf[p.l4Start : p.l4Start+2])
}

// DstPort returns the L4 destination port. Only valid when HasTransport is true.
func (p Packet) DstPort() uint16 {
	return readUint16(p.buf[p.l4Start+2 : p.l4Start+4])
}

// Bytes returns the (possibly Rewrite-mutated) backing buffer.
func (p Packet) Bytes() []byte { return p.buf }

// Rewrite replaces the packet's source and destination IP addresses in
// place and fixes up the affected checksums - the IPv4 header checksum and
// the TCP/UDP checksum (which covers the pseudo-header's addresses) - using
// RFC 1624 incremental updates. Cost is O(1): it never reads or copies the
// payload. Returns false if newSrc/newDst don't match the packet's address
// family or the buffer is too short to be a valid packet.
func (p Packet) Rewrite(newSrc, newDst netip.Addr) bool {
	if p.version == 4 {
		return p.rewriteV4(newSrc, newDst)
	}
	return p.rewriteV6(newSrc, newDst)
}

func (p Packet) rewriteV4(newSrc, newDst netip.Addr) bool {
	if !newSrc.Is4() || !newDst.Is4() || len(p.buf) < ipv4HeaderMinLen {
		return false
	}

	var oldAddrs, newAddrs [8]byte
	copy(oldAddrs[0:4], p.buf[12:16])
	copy(oldAddrs[4:8], p.buf[16:20])
	srcBytes, dstBytes := newSrc.As4(), newDst.As4()
	copy(newAddrs[0:4], srcBytes[:])
	copy(newAddrs[4:8], dstBytes[:])

	// IPv4 header checksum, offset 10-11.
	hc := readUint16(p.buf[10:12])
	writeUint16(p.buf[10:12], checksumAdjust(hc, oldAddrs[:], newAddrs[:]))

	if p.l4Start >= 0 {
		switch p.protocol {
		case ProtoTCP:
			if len(p.buf) >= p.l4Start+tcpHeaderMinLen {
				off := p.l4Start + 16
				csum := readUint16(p.buf[off : off+2])
				writeUint16(p.buf[off:off+2], checksumAdjust(csum, oldAddrs[:], newAddrs[:]))
			}
		case ProtoUDP:
			if len(p.buf) >= p.l4Start+udpHeaderLen {
				off := p.l4Start + 6
				csum := readUint16(p.buf[off : off+2])
				// 0x0000 means "checksum not computed" for IPv4/UDP and must
				// be left alone, never patched.
				if csum != 0 {
					newCsum := checksumAdjust(csum, oldAddrs[:], newAddrs[:])
					if newCsum == 0 {
						// 0 is reserved to mean "no checksum"; a genuine
						// zero result is transmitted as all-ones instead.
						newCsum = 0xffff
					}
					writeUint16(p.buf[off:off+2], newCsum)
				}
			}
		}
	}

	copy(p.buf[12:16], srcBytes[:])
	copy(p.buf[16:20], dstBytes[:])
	return true
}

func (p Packet) rewriteV6(newSrc, newDst netip.Addr) bool {
	if newSrc.Is4() || newDst.Is4() || len(p.buf) < ipv6HeaderLen {
		return false
	}

	var oldAddrs, newAddrs [32]byte
	copy(oldAddrs[0:16], p.buf[8:24])
	copy(oldAddrs[16:32], p.buf[24:40])
	srcBytes, dstBytes := newSrc.As16(), newDst.As16()
	copy(newAddrs[0:16], srcBytes[:])
	copy(newAddrs[16:32], dstBytes[:])

	// IPv6 has no header checksum of its own, only the L4 checksum (which
	// covers the pseudo-header's addresses) needs fixing up.
	if p.l4Start >= 0 {
		switch p.protocol {
		case ProtoTCP:
			if len(p.buf) >= p.l4Start+tcpHeaderMinLen {
				off := p.l4Start + 16
				csum := readUint16(p.buf[off : off+2])
				writeUint16(p.buf[off:off+2], checksumAdjust(csum, oldAddrs[:], newAddrs[:]))
			}
		case ProtoUDP:
			if len(p.buf) >= p.l4Start+udpHeaderLen {
				off := p.l4Start + 6
				csum := readUint16(p.buf[off : off+2])
				// Unlike IPv4, the UDP checksum is mandatory over IPv6
				// (RFC 8200 8.1) and must never be transmitted as 0.
				newCsum := checksumAdjust(csum, oldAddrs[:], newAddrs[:])
				if newCsum == 0 {
					newCsum = 0xffff
				}
				writeUint16(p.buf[off:off+2], newCsum)
			}
		}
	}

	copy(p.buf[8:24], srcBytes[:])
	copy(p.buf[24:40], dstBytes[:])
	return true
}
