#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/blk_mq_start_request")
int example(struct pt_regs *ctx)
{
    u64 a = ctx->r15;
    struct request *req = (struct request *)(ctx->di);
    unsigned int something_ns = BPF_CORE_READ(req, timeout);
    unsigned int data_len = BPF_CORE_READ(req, __data_len);
    bpf_printk("data length %lld %ld %ld\n", data_len,  something_ns, a);

    return 0;
}
