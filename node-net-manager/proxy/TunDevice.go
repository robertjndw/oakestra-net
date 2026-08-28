package proxy

import (
	"NetManager/logger"
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// TunDevice abstracts the platform TUN device the proxy reads outgoing
// packets from and writes ingoing ones to. ReadBatch/WriteBatch batch
// several packets into one syscall where the kernel supports it
// (BatchSize() > 1) - nothing above this interface may assume that support
// exists, since it is 1 on Darwin and on any Linux kernel that hasn't
// negotiated IFF_VNET_HDR.
//
// Every implementation - the real one and every test fake - shares one
// convention for where the packet sits within a buffer: index i of bufs
// occupies bufs[i][tunHeaderOffset : tunHeaderOffset+sizes[i]] on both Read
// and Write. See tunHeaderOffset for why that headroom exists at all; it
// lets the real adapter hand the platform buffers straight through with no
// copy, while keeping the interface itself free of a platform detail.
type TunDevice interface {
	// ReadBatch fills up to len(bufs) packets, reporting how many in the
	// return value and their individual lengths in sizes. A short read is
	// not an error - see ErrTooManySegments's handling in the real adapter,
	// which can turn a single oversized read into n=0, nil.
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
	// WriteBatch writes len(bufs) complete packets, coalescing them with
	// GRO where the kernel supports it. It may mutate bufs in the process;
	// the caller must not read them again afterwards assuming they are
	// unchanged.
	WriteBatch(bufs [][]byte) (int, error)
	// BatchSize is the most packets one Read/WriteBatch call can carry.
	BatchSize() int
	Name() string
	Close() error
}

// tunHeaderOffset is the headroom every buffer handed to Read/WriteBatch
// reserves before the packet itself. offset 0 is not safe on either platform
// this repo builds for - verified by reading golang.zx2c4.com/wireguard/tun's
// own Read/Write:
//
//   - Darwin's utun prepends a 4-byte address-family word: Write rejects
//     offset < 4 outright (io.ErrShortBuffer), and Read indexes
//     bufs[0][offset-4:], which panics on a negative slice bound at offset 0.
//   - Linux, once the kernel has negotiated IFF_VNET_HDR (i.e. whenever
//     BatchSize() > 1), needs 10 bytes immediately before the packet for the
//     virtio_net_hdr Write expects there: it computes offset -= 10 and
//     slices at that, which is also a negative (panicking) bound at offset 0.
//
// 10 covers both - the 6 spare bytes on Darwin, and on a pre-vnet_hdr Linux
// kernel where Write never even looks at the header room, are simply unused
// padding.
const tunHeaderOffset = 10

// wgTunDevice adapts golang.zx2c4.com/wireguard/tun's Device to TunDevice.
type wgTunDevice struct {
	dev tun.Device
}

func newWgTunDevice(dev tun.Device) *wgTunDevice {
	return &wgTunDevice{dev: dev}
}

func (w *wgTunDevice) ReadBatch(bufs [][]byte, sizes []int) (int, error) {
	n, err := w.dev.Read(bufs, sizes, tunHeaderOffset)
	if err != nil && errors.Is(err, tun.ErrTooManySegments) {
		// Documented on tun.ErrTooManySegments itself as non-fatal: the
		// kernel handed over a GSO superpacket with more segments than this
		// batch had buffers for. The segments beyond the batch are gone, but
		// the fd is still good - report nothing read rather than tearing the
		// read loop down.
		logger.ErrorLogger().Println("tun: dropped a GSO superpacket wider than the read batch:", err)
		return 0, nil
	}
	return n, err
}

func (w *wgTunDevice) WriteBatch(bufs [][]byte) (int, error) {
	return w.dev.Write(bufs, tunHeaderOffset)
}

func (w *wgTunDevice) BatchSize() int { return w.dev.BatchSize() }

func (w *wgTunDevice) Name() string {
	name, err := w.dev.Name()
	if err != nil {
		return ""
	}
	return name
}

func (w *wgTunDevice) Close() error { return w.dev.Close() }
