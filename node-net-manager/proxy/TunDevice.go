package proxy

import (
	"NetManager/logger"
	"errors"

	"golang.zx2c4.com/wireguard/tun"
)

// TunDevice abstracts the platform TUN device the proxy reads outgoing
// packets from and writes ingoing ones to. ReadBatch/WriteBatch coalesce
// several packets into one syscall where the kernel supports it
// (BatchSize() > 1 - it's 1 on Darwin and on Linux without IFF_VNET_HDR).
//
// Every implementation agrees on buffer layout: bufs[i][tunHeaderOffset :
// tunHeaderOffset+sizes[i]] holds the packet, on both Read and Write. See
// tunHeaderOffset for why the headroom exists.
type TunDevice interface {
	// A short read is not an error - see ErrTooManySegments's handling
	// below, which can turn an oversized read into n=0, nil.
	ReadBatch(bufs [][]byte, sizes []int) (int, error)
	// WriteBatch may mutate bufs; the caller must not read them again
	// afterwards assuming they're unchanged.
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
		// Non-fatal: a GSO superpacket had more segments than this batch had
		// buffers for. The extra segments are lost but the fd is still good.
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
