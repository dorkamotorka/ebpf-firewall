//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "parse_helpers.h"

struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC); // TODO: explain this
    __uint(max_entries, 65535);
} blocked_ips SEC(".maps");

SEC("xdp") 
int xdp_program(struct xdp_md *ctx) {
	void *data_end = (void *)(unsigned long long)ctx->data_end;
	void *data = (void *)(unsigned long long)ctx->data;
	struct hdr_cursor nh;
	nh.pos = data;

	// For simplicity we only showcase IPv4 firewalling 
	struct ethhdr *eth;
	int eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip;
		int ip_type = parse_iphdr(&nh, data_end, &ip);
		if ((void *)(ip + 1) > data_end) {
			goto out;
		}

		// ip->saddr bytes 'on the wire' are network order (big-endian): e.g. 7f 00 00 01 for 127.0.0.1.
		// But when the CPU loads that 32-bit value into a register, it treats it as a host-order integer and
		// if the host is little-endian, that effectively reverses how you interpret the bytes (e.g. like below but generally applicable).
		// bpf_ntohl() (“network to host long”) swaps the bytes IF AND ONLY IF your host machine is little-endian, otherwise
		// it simply returns the number as is.
		__u32 src = bpf_ntohl(ip->saddr); 

		struct ipv4_lpm_key key = {
			.prefixlen = 32,
			.data = src,
		};

		// The LPM (Longest Prefix Match) trie compares prefixes byte by byte,
		// starting from the most significant byte (data[0]).
		//
		// Unlike other eBPF map types, bpf_map_lookup_elem() on an LPM trie
		// can return a match even if the exact key is not present.
		// It returns the value associated with the *longest matching prefix*.
		// TODO: update this example based on the iximiuz tutorial
		// Example lookups for 10.0.10.123:
		//   10.0.0.0/8      -> match (covers 10.0.10.123)
		//   10.0.10.0/24    -> match (more specific prefix)
		//   10.0.10.123/32  -> match (exact prefix)
		//
		// The function returns:
		//   - NULL (or 0) if no matching prefix exists
		//   - A pointer to the value of the longest matching prefix otherwise
		// 
		// NOTE: We have set values for all prefixes to 1 (in user space) because we only case about the "match" but 
		// we could technically set different values and perform e.g. routing or enforce specific network policies based on it
		int *blocked = bpf_map_lookup_elem(&blocked_ips, &key);
		if (blocked && *blocked) {
			bpf_printk("%u.%u.%u.%u BLOCKED! (value=%d)",
				(src >> 24) & 0xFF,
				(src >> 16) & 0xFF,
				(src >> 8)  & 0xFF,
				 src        & 0xFF,
				*blocked);
		}
	}
	
out:
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
