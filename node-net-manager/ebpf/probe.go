package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// kernelVersion returns the running kernel's major.minor, parsed out of
// LINUX_VERSION_CODE (see linux/version.h's KERNEL_VERSION macro).
func kernelVersion() (major, minor int, err error) {
	code, err := features.LinuxVersionCode()
	if err != nil {
		return 0, 0, err
	}
	major = int(code >> 16)
	minor = int((code >> 8) & 0xff)
	return major, minor, nil
}

// probeRedirectPeer reports whether bpf_redirect_peer is usable from a
// SchedCLS (TC) program on this kernel. It is a real verifier probe (loads a
// throwaway program referencing the helper), not a version-number guess,
// because distros backport helpers independently of their advertised kernel
// version - see the plan's portability section.
func probeRedirectPeer() bool {
	return features.HaveProgramHelper(ebpf.SchedCLS, asm.FnRedirectPeer) == nil
}
