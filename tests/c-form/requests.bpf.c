#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/blk_mq_start_request")
int example(struct pt_regs *ctx)
{
    struct request *req = (struct request *)(ctx->di);
    u32 data_len = req->__data_len;
    bpf_printk("data length %u\n", data_len);

    return 0;
}
