package iputils

import "encoding/binary"

// Internet checksums (RFC 1071/1624) are one's-complement 16-bit sums.
// Translating a packet only ever rewrites the source/destination address
// fields, never the payload, so there is no need to walk the payload and
// recompute a checksum from scratch: RFC 1624 gives an O(1) way to update an
// existing checksum for a field replacement:
//
//	HC' = ~(~HC + ~m + m')   (all additions are one's-complement, i.e. with
//	                          end-around carry)
//
// which generalizes to replacing several 16-bit words at once by summing
// ~m_i for every old word and m'_i for every new word before folding.

// foldCarry reduces a 32-bit accumulator down to a 16-bit one's-complement
// sum by repeatedly folding the carry bits back in.
func foldCarry(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// checksumAdjust applies the RFC 1624 incremental update to checksum (as
// stored on the wire, big-endian) for replacing the bytes in old with the
// bytes in new. old and new must be the same length and an even number of
// bytes (they're read as consecutive 16-bit big-endian words).
func checksumAdjust(checksum uint16, old, new []byte) uint16 {
	sum := uint32(^checksum) & 0xffff
	for i := 0; i+1 < len(old); i += 2 {
		w := uint32(old[i])<<8 | uint32(old[i+1])
		sum += (^w) & 0xffff
	}
	for i := 0; i+1 < len(new); i += 2 {
		w := uint32(new[i])<<8 | uint32(new[i+1])
		sum += w
	}
	return ^foldCarry(sum)
}

func readUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func writeUint16(b []byte, v uint16) {
	binary.BigEndian.PutUint16(b, v)
}
