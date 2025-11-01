#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int print_xdp_data(struct xdp_md *ctx)
{
    // 'data' is a pointer to the start of packet data
    void *data = (void *)(long)ctx->data;

    bpf_printk("ctx->data = %p\n", data);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
