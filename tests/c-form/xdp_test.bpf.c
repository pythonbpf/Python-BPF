// xdp_ip_map.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct ip_key {
   __u8 family;     // 4 = IPv4
   __u8 pad[3];     // padding for alignment
   __u8 addr[16];   // IPv4 uses first 4 bytes
};

// key → packet count
struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __uint(max_entries, 16384);
   __type(key, struct ip_key);
   __type(value, __u64);
} ip_count_map SEC(".maps");

SEC("xdp")
int xdp_ip_map(struct xdp_md *ctx)
{
   void *data_end = (void *)(long)ctx->data_end;
   void *data     = (void *)(long)ctx->data;
   struct ethhdr *eth = data;

   if (eth + 1 > (struct ethhdr *)data_end)
       return XDP_PASS;

   __u16 h_proto = eth->h_proto;
   void *nh = data + sizeof(*eth);

   // VLAN handling: single tag
   if (h_proto == bpf_htons(ETH_P_8021Q) ||
       h_proto == bpf_htons(ETH_P_8021AD)) {

       if (nh + 4 > data_end)
           return XDP_PASS;

       h_proto = *(__u16 *)(nh + 2);
       nh += 4;
   }

   struct ip_key key = {};

   // IPv4
   if (h_proto == bpf_htons(ETH_P_IP)) {
       struct iphdr *iph = nh;
       if (iph + 1 > (struct iphdr *)data_end)
           return XDP_PASS;

       key.family = 4;
       // Copy 4 bytes of IPv4 address
       __builtin_memcpy(key.addr, &iph->saddr, 4);

       __u64 *val = bpf_map_lookup_elem(&ip_count_map, &key);
       if (val)
           (*val)++;
       else {
           __u64 init = 1;
           bpf_map_update_elem(&ip_count_map, &key, &init, BPF_ANY);
       }

       return XDP_PASS;
   }

   return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
