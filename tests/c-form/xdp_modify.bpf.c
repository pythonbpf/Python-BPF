// xdp_rewrite.c
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

SEC("xdp")
int xdp_rewrite_mac(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
    __u8 new_src[ETH_ALEN] = {0x02,0x00,0x00,0x00,0x00,0x02};
    for (int i = 0; i < ETH_ALEN; i++) eth->h_source[i] = new_src[i];

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
