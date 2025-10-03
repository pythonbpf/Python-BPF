// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

struct test_struct {
    __u64 a;
    __u64 b;
};

struct test_struct w = {};
volatile __u64 prev_time = 0;

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx)
{
    bpf_printk("previous %ul now %ul", w.b, w.a);
    __u64 ts = bpf_ktime_get_ns();
    bpf_printk("prev %ul now %ul", prev_time, ts);
    w.a = ts;
    w.b = prev_time;
    prev_time = ts;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
