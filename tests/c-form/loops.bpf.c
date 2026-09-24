/* Reference for loops. One program per shape the Python tests use, written
 * the way PythonBPF lowers them: a `for i in range(...)` keeps a hidden
 * induction counter separate from `i`, so rebinding `i` in the body cannot
 * change the trip count. The constant-bound cases fold to a `ret` at -O2;
 * `dyn_helper` reads its bound from a .data global and calls a helper per
 * iteration, so a real loop (and the verifier's bounded-loop check) survives.
 * (A helper-free sum over a runtime bound folds to a closed form that needs
 * the __multi3 libcall, which BPF lacks -- so it is not a useful reference.) */
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef long long __s64;

char LICENSE[] SEC("license") = "GPL";

__s64 n = 10;

/* for i in range(10): total = total + 1 */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 range_sum(void *ctx)
{
    __s64 total = 0;
    for (__s64 idx = 0; idx < 10; idx += 1) {
        __s64 i = idx;
        total = total + 1;
    }
    return total;
}

/* for i in range(0, 10, 2): total = total + i */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 range_step(void *ctx)
{
    __s64 total = 0;
    for (__s64 idx = 0; idx < 10; idx += 2) {
        __s64 i = idx;
        total = total + i;
    }
    return total;
}

/* while i < 10: i = i + 1 */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 while_basic(void *ctx)
{
    __s64 i = 0;
    while (i < 10)
        i = i + 1;
    return i;
}

/* while True: total += 1; if total == 10: break */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 while_true_break(void *ctx)
{
    __s64 total = 0;
    while (1) {
        total = total + 1;
        if (total == 10)
            break;
    }
    return total;
}

/* for i in range(10): if i % 2 == 0: continue; total = total + i */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 for_continue(void *ctx)
{
    __s64 total = 0;
    for (__s64 idx = 0; idx < 10; idx += 1) {
        __s64 i = idx;
        if (i % 2 == 0)
            continue;
        total = total + i;
    }
    return total;
}

static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;

/* for i in range(stop): total = total + random() -- a helper call per
 * iteration keeps the loop from folding, so the verifier sees a real loop.
 * The clamp is what makes it bounded: n is writable from userspace, so
 * unclamped the verifier walks iterations until E2BIG. */
SEC("tracepoint/syscalls/sys_enter_execve")
__s64 dyn_helper(void *ctx)
{
    __s64 total = 0;
    __s64 stop = n;
    if (stop > 64)
        stop = 64;
    for (__s64 idx = 0; idx < stop; idx += 1) {
        __s64 i = idx;
        total = total + bpf_get_prandom_u32();
    }
    return total;
}
