/* Minimal reference: the four C global-variable classes, nothing else.
 * No headers, so every line of IR is attributable. */
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;

__u64 counter;                    /* zero-init  -> .bss,    mutable      */
__u64 total = 7;                  /* init       -> .data,   mutable      */
const __u32 version = 3;          /* const      -> .rodata, clang folds  */
const volatile __u32 filter_pid;  /* cfg knob   -> .rodata, never folded */

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int prog(void *ctx)
{
    if (filter_pid == 0)
        return 0;
    counter += 1;
    total += version;
    return (int)counter;
}

char _license[] SEC("license") = "GPL";
