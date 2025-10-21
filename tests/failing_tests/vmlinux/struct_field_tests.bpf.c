// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp/syscalls/sys_enter_execve")
int handle_setuid_entry(struct trace_event_raw_sys_enter *ctx) {
  bpf_printk("args: %u", (unsigned int)ctx->args[0]);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
