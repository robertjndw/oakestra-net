package ebpf

import (
	"NetManager/logger"
	"errors"
	"net"

	"github.com/cilium/ebpf/perf"
)

// drainSlowpath runs on its own goroutine for the Manager's lifetime,
// reading VIP-miss notifications off the perf buffer and handing each to
// OnVIPMiss. It never blocks the datapath: tc_egress has already returned
// TC_ACT_OK for that packet by the time an event lands here (see the plan's
// "Slow path" section).
func (m *Manager) drainSlowpath() {
	for {
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.ErrorLogger().Println("ebpf: slowpath perf read:", err)
			continue
		}
		if record.LostSamples > 0 {
			logger.DebugLogger().Printf("ebpf: slowpath reader dropped %d events (userspace too slow)", record.LostSamples)
		}
		if len(record.RawSample) < 4 {
			continue
		}

		// oakestra.c writes ip->daddr verbatim (network byte order, i.e.
		// already the wire order of the four octets) - no byte swap needed.
		vip := net.IPv4(record.RawSample[0], record.RawSample[1], record.RawSample[2], record.RawSample[3])

		if cb := m.OnVIPMiss; cb != nil {
			go cb(vip)
		}
	}
}
