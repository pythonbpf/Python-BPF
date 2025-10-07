#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/do_unlinkat")
int kprobe_execve(struct pt_regs *ctx)
{
    bpf_printk("unlinkat created");
    return 0;
}

SEC("kretprobe/do_unlinkat")
int kretprobe_execve(struct pt_regs *ctx)
{
    bpf_printk("unlinkat returned\n");
    return 0;
}
