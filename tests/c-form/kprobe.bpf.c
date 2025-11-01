#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/do_unlinkat")
int kprobe_execve(struct pt_regs *ctx)
{
    bpf_printk("unlinkat created");

    unsigned long r15 = ctx->r15;
    bpf_printk("r15: %lld", r15);

    unsigned long r14 = ctx->r14;
    bpf_printk("r14: %lld", r14);

    unsigned long r13 = ctx->r13;
    bpf_printk("r13: %lld", r13);

    unsigned long r12 = ctx->r12;
    bpf_printk("r12: %lld", r12);

    unsigned long bp = ctx->bp;
    bpf_printk("rbp: %lld", bp);

    unsigned long bx = ctx->bx;
    bpf_printk("rbx: %lld", bx);

    unsigned long r11 = ctx->r11;
    bpf_printk("r11: %lld", r11);

    unsigned long r10 = ctx->r10;
    bpf_printk("r10: %lld", r10);

    unsigned long r9 = ctx->r9;
    bpf_printk("r9: %lld", r9);

    unsigned long r8 = ctx->r8;
    bpf_printk("r8: %lld", r8);

    unsigned long ax = ctx->ax;
    bpf_printk("rax: %lld", ax);

    unsigned long cx = ctx->cx;
    bpf_printk("rcx: %lld", cx);

    unsigned long dx = ctx->dx;
    bpf_printk("rdx: %lld", dx);

    unsigned long si = ctx->si;
    bpf_printk("rsi: %lld", si);

    unsigned long di = ctx->di;
    bpf_printk("rdi: %lld", di);

    unsigned long orig_ax = ctx->orig_ax;
    bpf_printk("orig_rax: %lld", orig_ax);

    unsigned long ip = ctx->ip;
    bpf_printk("rip: %lld", ip);

    unsigned long cs = ctx->cs;
    bpf_printk("cs: %lld", cs);

    unsigned long flags = ctx->flags;
    bpf_printk("eflags: %lld", flags);

    unsigned long sp = ctx->sp;
    bpf_printk("rsp: %lld", sp);

    unsigned long ss = ctx->ss;
    bpf_printk("ss: %lld", ss);

    return 0;
}
