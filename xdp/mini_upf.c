#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>

#ifndef IP_MF
#define IP_MF 0x2000
#endif
#ifndef IP_OFFSET
#define IP_OFFSET 0x1FFF
#endif

/* GTP-U decap + TEID-based forwarding for an uplink-only mini UPF. */
#define GTPU_PORT 2152
#define GTPU_FLAGS 0x30
#define GTPU_MSGTYPE_TPDU 0xff

#define TEID_FWD_ENTRIES 4096
#define TEID_STATS_ENTRIES 4096

/* TEID -> uplink forwarding metadata: egress ifindex and outer MACs. */
struct teid_fwd {
	__u32 out_ifindex;
	__u8 dst_mac[ETH_ALEN];
	__u8 src_mac[ETH_ALEN];
	__u8 next_hop_ip[16]; /* Optional placeholder for IPv4/IPv6 next-hop */
};

/* Per-TEID accounting for packets/bytes/misses. */
struct teid_stats {
	__u64 pkts;
	__u64 bytes;
	__u64 lookup_miss;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TEID_FWD_ENTRIES);
	__type(key, __u32);
	__type(value, struct teid_fwd);
} teid_fwd SEC("maps");

/* Per-TEID counters: packets, bytes, and lookup miss stats. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TEID_STATS_ENTRIES);
	__type(key, __u32);
	__type(value, struct teid_stats);
} teid_stats SEC("maps");

/* Allowed ingress interface (N3). If unset, any ingress is accepted. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ingress_if SEC("maps");

struct gtpv1_hdr {
	__u8 flags;
	__u8 msg_type;
	__be16 length;
	__be32 teid;
};

/* Initialize-on-first-use helper: bump hit counters for a TEID. */
static __always_inline void update_stats_hit(__u32 teid, __u64 bytes)
{
	struct teid_stats *s = bpf_map_lookup_elem(&teid_stats, &teid);
	if (!s) {
		struct teid_stats init = {};
		bpf_map_update_elem(&teid_stats, &teid, &init, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&teid_stats, &teid);
	}
	if (s) {
		__sync_fetch_and_add(&s->pkts, 1);
		__sync_fetch_and_add(&s->bytes, bytes);
	}
}

/* Initialize-on-first-use helper: bump lookup miss counter for a TEID. */
static __always_inline void update_stats_miss(__u32 teid)
{
	struct teid_stats *s = bpf_map_lookup_elem(&teid_stats, &teid);
	if (!s) {
		struct teid_stats init = {};
		bpf_map_update_elem(&teid_stats, &teid, &init, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&teid_stats, &teid);
	}
	if (s)
		__sync_fetch_and_add(&s->lookup_miss, 1);
}

/* Allow only the configured N3 ifindex; treat 0/unset as allow-all. */
static __always_inline bool check_ingress_if(__u32 ingress_ifindex)
{
	__u32 key = 0;
	__u32 *expected = bpf_map_lookup_elem(&ingress_if, &key);
	if (!expected || *expected == 0)
		return true; /* If not configured, allow */
	return *expected == ingress_ifindex;
}

/* XDP entrypoint: validate ingress, parse outer IPv4/IPv6 UDP GTP-U, lookup TEID,
 * decapsulate to the inner payload, rewrite outer L2, and redirect toward N6.
 */
SEC("xdp/mini_upf")
int mini_upf(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	__u16 eth_proto;
	bool is_ipv6 = false;
	__u32 ingress_ifindex = ctx->ingress_ifindex;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	/* Enforce the configured N3 interface; otherwise pass the packet. */
	if (!check_ingress_if(ingress_ifindex))
		return XDP_PASS;

	eth_proto = bpf_ntohs(eth->h_proto);
	void *cursor = eth + 1;

	struct udphdr *udp;
	struct gtpv1_hdr *gtp;
	__u32 teid;
	__u64 payload_len = 0;

	if (eth_proto == ETH_P_IP) {
		struct iphdr *iph = cursor;
		if ((void *)(iph + 1) > data_end)
			return XDP_PASS;
		/* Only decap UDP/GTP-U; drop fragments to keep parsing simple. */
		if (iph->protocol != IPPROTO_UDP)
			return XDP_PASS;
		if (iph->ihl < 5)
			return XDP_PASS;
		if (iph->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return XDP_PASS;
		cursor = (void *)iph + iph->ihl * 4;
	} else if (eth_proto == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = cursor;
		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		if (ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		/* IPv6 extension headers are not handled */
		cursor = ip6 + 1;
		is_ipv6 = true;
	} else {
		return XDP_PASS;
	}

	udp = cursor;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;
	if (udp->dest != bpf_htons(GTPU_PORT))
		return XDP_PASS;

	gtp = (void *)(udp + 1);
	if ((void *)(gtp + 1) > data_end)
		return XDP_PASS;
	/* Require GTP-U TPDU; anything else is passed unchanged. */
	if (gtp->flags != GTPU_FLAGS || gtp->msg_type != GTPU_MSGTYPE_TPDU)
		return XDP_PASS;

	teid = bpf_ntohl(gtp->teid);
	payload_len = bpf_ntohs(gtp->length);
	void *inner = (void *)(gtp + 1);
	if ((void *)((char *)inner + payload_len) > data_end)
		return XDP_PASS;

	struct teid_fwd *fwd = bpf_map_lookup_elem(&teid_fwd, &teid);
	if (!fwd) {
		/* No TEID entry means drop in this uplink-only path. */
		update_stats_miss(teid);
		return XDP_DROP;
	}

	update_stats_hit(teid, payload_len);

	long offset_to_inner = (char *)(gtp + 1) - (char *)data;
	long adjust = offset_to_inner - (long)sizeof(struct ethhdr);
	if (adjust < 0)
		return XDP_ABORTED;

	/* Trim outer Ethernet/IP/UDP/GTP-U so the inner packet becomes the new head. */
	if (bpf_xdp_adjust_head(ctx, adjust))
		return XDP_ABORTED;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;

	if ((void *)(eth + 1) > data_end)
		return XDP_ABORTED;

	/* Set outer L2 for N6 egress. */
	__builtin_memcpy(eth->h_dest, fwd->dst_mac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fwd->src_mac, ETH_ALEN);
	eth->h_proto = bpf_htons(is_ipv6 ? ETH_P_IPV6 : ETH_P_IP);

	if (!fwd->out_ifindex)
		return XDP_ABORTED;

	/* Redirect toward N6 using the configured egress ifindex. */
	return bpf_redirect(fwd->out_ifindex, 0);
}

char _license[] SEC("license") = "GPL";
