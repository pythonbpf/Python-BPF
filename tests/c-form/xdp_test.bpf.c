#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct fake_iphdr {
  unsigned short useless;
  unsigned short tot_len;
  unsigned short id;
  unsigned short frag_off;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short check;
  unsigned int saddr;
  unsigned int daddr;
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  unsigned long data = ctx->data;
  unsigned long data_end = ctx->data_end;

  if (data + sizeof(struct ethhdr) + sizeof(struct fake_iphdr) > data_end) {
    return XDP_ABORTED;
  }
  struct fake_iphdr *iph = (void *)data + sizeof(struct ethhdr);

  bpf_printk("%d", iph->saddr);

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
