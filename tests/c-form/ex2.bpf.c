#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int hello(struct xdp_md *ctx) {
    bpf_printk("Hello, World! %ud \n", ctx->data);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
