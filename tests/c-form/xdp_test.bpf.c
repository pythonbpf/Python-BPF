#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct fake_iphdr {
    unsigned short useless;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
};

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_ABORTED;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct fake_iphdr *iph = (struct fake_iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_ABORTED;
    bpf_printk("%d", iph->saddr);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
