# make bpf regenerates ebpf/bpf_bpfel.go and ebpf/bpf_bpfel.o from
# ebpf/bpf/oakestra.c. Run deliberately on a Linux dev box with clang and
# libbpf headers installed (e.g. `apt install clang llvm libbpf-dev
# linux-libc-dev` on Debian/Ubuntu) - it is not part of `build/build.sh` or
# any CI workflow, since neither needs a C toolchain today and this target
# would be the only thing to require one.
#
# The generated files ARE committed (see .gitignore's note that it covers
# *.so and bin/ but not *.o), so `go build`/`go test` never need clang.

BPF_CLANG      ?= clang
BPF_CFLAGS     := -O2 -g -Wall -target bpfel
BPF_MULTIARCH  := $(shell gcc -print-multiarch 2>/dev/null)
BPF_INCLUDES   := -I/usr/include/bpf -I/usr/include -I/usr/include/$(BPF_MULTIARCH)

.PHONY: bpf
bpf:
	cd ebpf && go run github.com/cilium/ebpf/cmd/bpf2go \
		-type ip_addr -type backend -type service_backends_val \
		-type flow_key -type flow_ct_val -type flow_ct_rev_val \
		-type local_instance_val -type cfg_val \
		-target bpfel -cc $(BPF_CLANG) -go-package ebpf \
		bpf bpf/oakestra.c -- $(BPF_CFLAGS) $(BPF_INCLUDES)
