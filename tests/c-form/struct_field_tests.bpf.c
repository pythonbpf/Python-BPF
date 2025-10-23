// SPDX-License-Identifier: GPL-2.0

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
Information gained from reversing this (multiple kernel versions):
There is no point of
```llvm
 tail call void @llvm.dbg.value(metadata ptr %0, metadata !60, metadata !DIExpression()), !dbg !70
 ```
 and the first argument of passthrough is fucking useless. It just needs to be a distinct integer:
 ```llvm
   %9 = tail call ptr @llvm.bpf.passthrough.p0.p0(i32 3, ptr %8)
 ```
*/

SEC("tp/syscalls/sys_enter_execve")
int handle_setuid_entry(struct trace_event_raw_sys_enter *ctx) {
  // Access each argument separately with clear variable assignments
  long int arg0 = ctx->id;
  bpf_printk("args[0]: %d", arg0);

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
