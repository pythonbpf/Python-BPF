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
  long int id = ctx->id;
  bpf_printk("This is context field %d", id);
  /*
   * the IR to aim for is
   * %2 = alloca ptr, align 8
   * store ptr %0, ptr %2, align 8
   * Above, %0 is the arg pointer
   * %5 = load ptr, ptr %2, align 8
   * %6 = getelementptr inbounds %struct.trace_event_raw_sys_enter, ptr %5, i32 0, i32 2
   * %7 = load i64, ptr @"llvm.trace_event_raw_sys_enter:0:16$0:2:0", align 8
   * %8 = bitcast ptr %5 to ptr
   * %9 = getelementptr i8, ptr %8, i64 %7
   * %10 = bitcast ptr %9 to ptr
   * %11 = call ptr @llvm.bpf.passthrough.p0.p0(i32 0, ptr %10)
   * %12 = load i64, ptr %11, align 8, !dbg !101
   *
   */
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
