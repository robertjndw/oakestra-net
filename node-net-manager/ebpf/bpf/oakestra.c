// SPDX-License-Identifier: Apache-2.0

// TC fast path for Oakestra's semantic overlay: translation + encap/decap for
// the ProxyTUN datapath, kept as an accelerator rather than a replacement.
//
// Every program here returns TC_ACT_OK on anything it does not fully
// understand (unknown VIP, IPv6, ICMP, fragments, options-bearing headers,
// map miss). The packet then continues into the bridge -> route -> TUN ->
// existing Go path unchanged, so this can only make traffic faster, never
// make it fail.
//
// Portability floor is kernel 5.4 on ARM edge boards with no BTF and no
// libbpf CO-RE toolchain guaranteed present, so:
//   - no CO-RE, no vmlinux.h, no kernel struct access. Only __sk_buff (stable
//     UAPI) fields and raw packet bytes via data/data_end.
//   - no .rodata globals (needs 5.2 + mmap-able arrays); config lives in the
//     `cfg` ARRAY map instead.
//   - bpf_redirect_peer is 5.10+ and is feature-probed from the Go loader at
//     startup (see ebpf/probe.go). Below that floor every local redirect
//     falls back to plain bpf_redirect() via the host-side veth, which works
//     on every kernel in the support window but costs one extra hop.

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_BACKENDS 16
/* outer IPv4 (20) + outer UDP (8), see the ADJ_ROOM_ENCAP call below */
#define TUNNEL_HDR_LEN 28

#define POLICY_INSTANCE_NUMBER 0
#define POLICY_ROUND_ROBIN 1
#define POLICY_CLOSEST 2

/* All addresses are stored v4-mapped (::ffff:a.b.c.d) so the v6 path (M3)
 * can reuse this exact layout; only IPv4 traffic is handled through M2. */
struct ip_addr {
	__u8 addr[16];
};

struct backend {
	struct ip_addr nsip;
	struct ip_addr node_ip;
	__u16 node_port;
	__u8 on_this_node;
	__u8 pad;
};

struct service_backends_val {
	__u8 policy;
	__u8 pad[3];
	__u32 count;
	struct backend backends[MAX_BACKENDS];
};

struct flow_key {
	struct ip_addr saddr;
	struct ip_addr daddr;
	__u16 sport;
	__u16 dport;
	__u8 proto;
	__u8 pad[3];
};

struct flow_ct_val {
	struct ip_addr backend_nsip;
	struct ip_addr node_ip;
	__u16 node_port;
	__u8 pad[2];
	struct ip_addr src_instance_ip;
};

struct flow_ct_rev_val {
	struct ip_addr orig_src_nsip;
	struct ip_addr orig_dst_vip;
};

struct local_instance_val {
	/* Host-side veth ifindex (root netns) - always valid, used by the
	 * bpf_redirect() fallback. */
	__u32 veth_ifindex;
	/* Container-side (peer) veth ifindex. Only meaningful together with
	 * bpf_redirect_peer(): ifindex numbers are per-netns, so this value
	 * must never be handed to plain bpf_redirect(). */
	__u32 peer_ifindex;
};

struct cfg_val {
	__u32 nic_ifindex;
	struct ip_addr node_ip;
	__u16 tunnel_port;
	/* bpf_redirect_peer is 5.10+ and feature-probed from the Go loader at
	 * startup (see ebpf/probe.go); until then every local redirect takes
	 * the bpf_redirect() fallback via the host-side veth, one extra hop. */
	__u8 have_redirect_peer;
	__u8 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ip_addr);
	__type(value, struct service_backends_val);
} service_backends SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_ct_val);
} flow_ct SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct flow_key);
	__type(value, struct flow_ct_rev_val);
} flow_ct_rev SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ip_addr);
	__type(value, struct local_instance_val);
} local_instances SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct ip_addr);
	__type(value, struct ip_addr);
} instance_ip SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cfg_val);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} slowpath SEC(".maps");

/* ---- helpers ---------------------------------------------------------- */

static __always_inline void ipv4_to_mapped(__u32 be_addr, struct ip_addr *out)
{
	__builtin_memset(out->addr, 0, 10);
	out->addr[10] = 0xff;
	out->addr[11] = 0xff;
	__builtin_memcpy(&out->addr[12], &be_addr, 4);
}

static __always_inline __u32 mapped_to_ipv4(const struct ip_addr *in)
{
	__u32 be_addr;
	__builtin_memcpy(&be_addr, &in->addr[12], 4);
	return be_addr;
}

static __always_inline __u32 fnv_mix(__u32 h, __u32 v)
{
	h ^= v;
	h *= 16777619u;
	return h;
}

/* FNV-1a-style mix over the 5-tuple's meaningful bytes only (the real IPv4
 * octets, not the 12-byte v4-mapped prefix); used only for RoundRobin
 * backend selection, where per-flow affinity (not uniformity) is the point -
 * see the plan's note on ProxyTunnel.go's fixed-seed PRNG picking the
 * identical sequence on every node in the cluster.
 *
 * Deliberately not a byte-at-a-time #pragma-unroll loop over the full
 * 36-byte key: at that unroll width the verifier's precision-tracking
 * backward walk (mark_precise) fails with "math between map_value pointer
 * and register with unbounded min value" once a map-value pointer is also
 * live in the caller's scope - a real verifier limitation, not a logic bug.
 * Four fixed-width mixes stay well clear of it. */
static __always_inline __u32 flow_hash(const struct flow_key *key)
{
	__u32 h = 2166136261u;
	__u32 saddr, daddr;

	__builtin_memcpy(&saddr, &key->saddr.addr[12], 4);
	__builtin_memcpy(&daddr, &key->daddr.addr[12], 4);

	h = fnv_mix(h, saddr);
	h = fnv_mix(h, daddr);
	h = fnv_mix(h, ((__u32)key->sport << 16) | key->dport);
	h = fnv_mix(h, key->proto);
	return h;
}

static __always_inline struct backend *
select_backend(struct service_backends_val *svc, const struct flow_key *key)
{
	__u32 count = svc->count;

	if (count == 0 || count > MAX_BACKENDS)
		return NULL;
	barrier_var(count); /* see the barrier_var(ct) comment below */

	/* Not a switch: a switch here (even a two-case one) makes idx's value
	 * depend on which arm ran in a way the verifier's precision tracking
	 * couldn't resolve once svc (a map-value pointer) was also live -
	 * same failure class as flow_hash's old unrolled loop, see above. A
	 * plain ternary keeps idx's provenance simple enough to verify. */
	__u32 idx = (svc->policy == POLICY_ROUND_ROBIN) ? (flow_hash(key) % count) : 0;
	barrier_var(idx);

	if (idx >= MAX_BACKENDS)
		return NULL;
	return &svc->backends[idx];
}

static __always_inline int redirect_to_local(const struct cfg_val *c,
					       const struct local_instance_val *local)
{
	/* bpf_redirect_peer takes the ifindex resolvable in *this* netns (the
	 * host-side veth, same one bpf_redirect would use) and redirects to
	 * *its peer*, switching netns ingress-to-ingress without a backlog
	 * queue round trip - it does not take the peer's own ifindex number,
	 * which lives in a different netns and isn't resolvable here anyway. */
	if (c->have_redirect_peer)
		return bpf_redirect_peer(local->veth_ifindex, 0);
	return bpf_redirect(local->veth_ifindex, 0);
}

/* ---- tc_egress: container -> world ------------------------------------ */

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK; /* IPv6/ARP/etc fall through to ProxyTUN (M3) */

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;
	if (ip->ihl != 5)
		return TC_ACT_OK; /* options present, let userspace handle it */
	if (ip->frag_off & bpf_htons(0x3FFF))
		return TC_ACT_OK; /* fragment, defrag stays in userspace */
	if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK; /* ICMP and friends fall through */

	__u16 sport, dport;
	__u16 l4_csum_off;
	__u8 is_tcp = (ip->protocol == IPPROTO_TCP);

	if (is_tcp) {
		struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		sport = tcp->source;
		dport = tcp->dest;
		l4_csum_off = ((void *)&tcp->check - data);
	} else {
		struct udphdr *udp = (void *)ip + (ip->ihl * 4);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		sport = udp->source;
		dport = udp->dest;
		l4_csum_off = ((void *)&udp->check - data);
	}

	struct ip_addr vip;
	ipv4_to_mapped(ip->daddr, &vip);
	/* Compiler barrier: without it, clang inlines this call site and the
	 * one below into tc_egress and, on this exact function shape, the
	 * combination confuses SROA+InstCombine into deciding the `cfg` map
	 * lookup result is unreachable ("br i1 undef"), collapsing the whole
	 * function to an unconditional TC_ACT_OK. Confirmed via bisection
	 * against clang 14 and clang 18. tc_decap inlines the same helper
	 * twice too without issue, so the trigger is specific to this
	 * function's surrounding code, not the helper in isolation. A BPF
	 * subprogram call (noinline) also fixes it but hits a separate,
	 * apparently genuine verifier limitation around precision tracking
	 * for map-value pointers spilled across a call boundary - a plain
	 * barrier() is the narrower, lower-risk fix. */
	barrier();

	/* Only the Service VIP subnetwork (10.30.0.0/16) is ours; anything else
	 * is regular traffic the bridge should route as today. */
	if ((ip->daddr & bpf_htonl(0xFFFF0000)) != bpf_htonl(0x0A1E0000))
		return TC_ACT_OK;

	__u32 cfg_key = 0;
	struct cfg_val *c = bpf_map_lookup_elem(&cfg, &cfg_key);
	if (!c)
		return TC_ACT_OK; /* not configured yet, e.g. still starting up */
	barrier_var(c); /* see the barrier_var(ct) comment further down */

	struct flow_key fkey = {};
	ipv4_to_mapped(ip->saddr, &fkey.saddr);
	barrier(); /* see the comment on the first ipv4_to_mapped call above */
	fkey.daddr = vip;
	fkey.sport = sport;
	fkey.dport = dport;
	fkey.proto = ip->protocol;

	struct flow_ct_val *ct = bpf_map_lookup_elem(&flow_ct, &fkey);
	struct flow_ct_val newct;

	if (!ct) {
		struct service_backends_val *svc =
			bpf_map_lookup_elem(&service_backends, &vip);
		if (!svc) {
			/* Slow path: notify userspace of the VIP miss and let the
			 * packet ride the existing TUN path for this (and only
			 * this) packet - see plan's "Slow path" section. */
			__u32 vip_evt = ip->daddr;
			bpf_perf_event_output(skb, &slowpath, BPF_F_CURRENT_CPU,
					       &vip_evt, sizeof(vip_evt));
			return TC_ACT_OK;
		}

		struct backend *b = select_backend(svc, &fkey);
		if (!b)
			return TC_ACT_OK;

		struct ip_addr *instance_ip_val =
			bpf_map_lookup_elem(&instance_ip, &fkey.saddr);
		if (!instance_ip_val)
			return TC_ACT_OK; /* not one of ours (yet); let userspace handle it */

		__builtin_memset(&newct, 0, sizeof(newct));
		newct.backend_nsip = b->nsip;
		newct.node_ip = b->node_ip;
		newct.node_port = b->node_port;
		newct.src_instance_ip = *instance_ip_val;
		bpf_map_update_elem(&flow_ct, &fkey, &newct, BPF_ANY);

		struct flow_key rkey = {
			.saddr = b->nsip,
			.daddr = *instance_ip_val,
			.sport = dport,
			.dport = sport,
			.proto = ip->protocol,
		};
		struct flow_ct_rev_val rval = {
			.orig_src_nsip = fkey.saddr,
			.orig_dst_vip = vip,
		};
		bpf_map_update_elem(&flow_ct_rev, &rkey, &rval, BPF_ANY);

		ct = &newct;
	}
	/* Without this, clang hoists address arithmetic on `ct` (e.g. &ct->x
	 * for a later csum/map call) above this branch, since plain pointer
	 * arithmetic - as opposed to a dereference - is legal on a possibly-
	 * null pointer in normal C. The verifier is stricter: any arithmetic
	 * on a still-nullable map-value register is rejected outright ("R6
	 * pointer arithmetic on map_value_or_null prohibited"). barrier_var
	 * forces the branch-resolved, now-non-null value to be materialized
	 * before anything downstream can be computed from it. */
	barrier_var(ct);

	/* Rewrite src (instance IP) and dst (backend nsip) in place. */
	__u32 old_daddr = ip->daddr;
	__u32 old_saddr = ip->saddr;
	__u32 new_daddr = mapped_to_ipv4(&ct->backend_nsip);
	__u32 new_saddr = mapped_to_ipv4(&ct->src_instance_ip);

	/* skb byte offsets are absolute (from the start of the frame), not
	 * relative to the IP header - every offsetof(struct iphdr, ...) below
	 * needs ETH_HLEN added, or these land inside the Ethernet header
	 * instead of the IP header and corrupt the frame. l4_csum_off is
	 * already absolute (computed via pointer difference from `data`
	 * further up), so it does not need the same adjustment. */
	bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			     old_daddr, new_daddr, 4);
	bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			     old_saddr, new_saddr, 4);
	bpf_l4_csum_replace(skb, l4_csum_off, old_daddr, new_daddr,
			     4 | BPF_F_PSEUDO_HDR);
	bpf_l4_csum_replace(skb, l4_csum_off, old_saddr, new_saddr,
			     4 | BPF_F_PSEUDO_HDR);

	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
				 &new_daddr, 4, 0) < 0)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
				 &new_saddr, 4, 0) < 0)
		return TC_ACT_OK;

	struct local_instance_val *local =
		bpf_map_lookup_elem(&local_instances, &ct->backend_nsip);
	if (local) {
		/* Node-local backend: no encap, straight redirect to the
		 * target veth (plan's "(local)" row). */
		return redirect_to_local(c, local);
	}

	if (bpf_skb_adjust_room(skb, TUNNEL_HDR_LEN, BPF_ADJ_ROOM_MAC,
				 BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
					 BPF_F_ADJ_ROOM_ENCAP_L4_UDP) < 0)
		return TC_ACT_OK; /* would not fit under MTU; fall through */

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	struct iphdr *outer_ip = (void *)(eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		return TC_ACT_OK;

	struct udphdr *outer_udp = (void *)(outer_ip + 1);
	if ((void *)(outer_udp + 1) > data_end)
		return TC_ACT_OK;

	struct iphdr *inner_ip_probe = (void *)outer_ip + TUNNEL_HDR_LEN;
	if ((void *)(inner_ip_probe + 1) > data_end)
		return TC_ACT_OK;
	__u16 inner_total_len = bpf_ntohs(inner_ip_probe->tot_len);

	__builtin_memset(outer_ip, 0, sizeof(*outer_ip));
	outer_ip->version = 4;
	outer_ip->ihl = 5;
	outer_ip->ttl = 64;
	outer_ip->protocol = IPPROTO_UDP;
	outer_ip->tot_len = bpf_htons(TUNNEL_HDR_LEN + inner_total_len);
	outer_ip->saddr = mapped_to_ipv4(&c->node_ip);
	outer_ip->daddr = mapped_to_ipv4(&ct->node_ip);
	outer_ip->check = 0; /* recomputed below via l3_csum_replace from 0 */

	outer_udp->source = bpf_htons(c->tunnel_port);
	outer_udp->dest = bpf_htons(ct->node_port);
	outer_udp->len = bpf_htons(sizeof(*outer_udp) + inner_total_len);
	outer_udp->check = 0; /* legal (and cheaper) to leave at 0 for IPv4 */

	/* Fresh 20-byte header, so compute the checksum directly rather than
	 * incrementally patching one that was never valid to begin with. */
	{
		__u32 csum = 0;
		__u16 *words = (void *)outer_ip;

		if ((void *)(words + 10) > data_end)
			return TC_ACT_OK;
#pragma unroll
		for (int i = 0; i < 10; i++)
			csum += words[i];
		csum = (csum & 0xFFFF) + (csum >> 16);
		csum = (csum & 0xFFFF) + (csum >> 16);
		outer_ip->check = ~csum;
	}

	return bpf_redirect(c->nic_ifindex, 0);
}

/* ---- tc_decap: world -> container -------------------------------------- */

SEC("tc/decap")
int tc_decap(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	struct iphdr *outer_ip = (void *)(eth + 1);
	if ((void *)(outer_ip + 1) > data_end)
		return TC_ACT_OK;
	if (outer_ip->ihl != 5 || outer_ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	struct udphdr *outer_udp = (void *)(outer_ip + 1);
	if ((void *)(outer_udp + 1) > data_end)
		return TC_ACT_OK;

	__u32 cfg_key = 0;
	struct cfg_val *c = bpf_map_lookup_elem(&cfg, &cfg_key);
	if (!c)
		return TC_ACT_OK;
	if (outer_udp->dest != bpf_htons(c->tunnel_port))
		return TC_ACT_OK; /* not tunnel traffic, e.g. control plane */

	struct iphdr *inner_ip = (void *)(outer_udp + 1);
	if ((void *)(inner_ip + 1) > data_end)
		return TC_ACT_OK;
	if (inner_ip->ihl != 5)
		return TC_ACT_OK;
	if (inner_ip->protocol != IPPROTO_TCP && inner_ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	__u16 sport, dport;

	if (inner_ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(inner_ip + 1);
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		sport = tcp->source;
		dport = tcp->dest;
	} else {
		struct udphdr *udp = (void *)(inner_ip + 1);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		sport = udp->source;
		dport = udp->dest;
	}

	/* Both directions were inserted by tc_egress at flow creation, so no
	 * tuple canonicalization is needed here - the reverse tuple is an
	 * exact key as observed on the wire. */
	struct flow_key rkey = {};
	ipv4_to_mapped(inner_ip->saddr, &rkey.saddr);
	ipv4_to_mapped(inner_ip->daddr, &rkey.daddr);
	rkey.sport = sport;
	rkey.dport = dport;
	rkey.proto = inner_ip->protocol;

	struct flow_ct_rev_val *rev = bpf_map_lookup_elem(&flow_ct_rev, &rkey);
	if (!rev)
		return TC_ACT_OK; /* unknown flow, let ProxyTUN handle/reject it */

	struct local_instance_val *local =
		bpf_map_lookup_elem(&local_instances, &rev->orig_src_nsip);
	if (!local)
		return TC_ACT_OK; /* the target container is not local anymore */

	__u32 new_daddr = mapped_to_ipv4(&rev->orig_src_nsip);
	__u32 new_saddr = mapped_to_ipv4(&rev->orig_dst_vip);

	if (bpf_skb_adjust_room(skb, -TUNNEL_HDR_LEN, BPF_ADJ_ROOM_MAC, 0) < 0)
		return TC_ACT_OK;

	data = (void *)(long)skb->data;
	data_end = (void *)(long)skb->data_end;
	eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	__u32 old_daddr = ip->daddr;
	__u32 old_saddr = ip->saddr;
	__u16 l4_csum_off;

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp = (void *)(ip + 1);
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		l4_csum_off = ((void *)&tcp->check - data);
	} else {
		struct udphdr *udp = (void *)(ip + 1);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		l4_csum_off = ((void *)&udp->check - data);
	}

	/* Absolute skb offsets again - see the comment on the equivalent block
	 * in tc_egress. */
	bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			     old_daddr, new_daddr, 4);
	bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check),
			     old_saddr, new_saddr, 4);
	bpf_l4_csum_replace(skb, l4_csum_off, old_daddr, new_daddr,
			     4 | BPF_F_PSEUDO_HDR);
	bpf_l4_csum_replace(skb, l4_csum_off, old_saddr, new_saddr,
			     4 | BPF_F_PSEUDO_HDR);

	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, daddr),
				 &new_daddr, 4, 0) < 0)
		return TC_ACT_OK;
	if (bpf_skb_store_bytes(skb, ETH_HLEN + offsetof(struct iphdr, saddr),
				 &new_saddr, 4, 0) < 0)
		return TC_ACT_OK;

	return redirect_to_local(c, local);
}

/* The source file itself stays Apache-2.0 (see the SPDX tag above) - this
 * is the separate, kernel-facing runtime license gate. bpf_perf_event_output
 * (the slowpath punt) is GPL_ONLY in the kernel, and the verifier rejects
 * loading the whole program under a non-GPL-compatible tag. "Dual BSD/GPL"
 * is the standard way eBPF C is tagged to satisfy that gate without
 * relicensing the source; Cilium's own datapath C files do the same. */
char _license[] SEC("license") = "Dual BSD/GPL";
