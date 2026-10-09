/* Reference for passing a map lookup result to a helper. `prev` is a local
 * holding the pointer bpf_map_lookup_elem returned; bpf_map_update_elem gets
 * that pointer (the map value), loaded from prev's slot. It never gets &prev,
 * the slot's own address, which would make the map store a stack address.
 * The clang -O0 IR for this file is the specification for the pointer depth
 * that tests/test_signedness_ir.py checks:
 *   copy()   mirrors passing_tests/helpers/map_update_from_lookup.py
 *   rebind() mirrors passing_tests/vmlinux/named_arg.py, where `prev = prev + 1`
 *            rebinds prev to a stack temporary holding the sum; the helper
 *            still gets the pointer loaded from prev's slot. */
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
typedef long long __s64;

#define BPF_MAP_TYPE_HASH 1
#define BPF_ANY 0
#define XDP_PASS 2

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                   const void *value, __s64 flags) = (void *)2;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, __s64);
    __type(value, __s64);
} count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_getpid")
__s64 copy(void *ctx)
{
    __s64 key = 0;
    __s64 *prev = bpf_map_lookup_elem(&count, &key);
    if (prev) {
        key = 1;
        bpf_map_update_elem(&count, &key, prev, BPF_ANY);
    }
    return 0;
}

SEC("xdp")
__s64 rebind(void *ctx)
{
    __s64 key = 0;
    __s64 tmp;
    __s64 *prev = bpf_map_lookup_elem(&count, &key);
    if (prev) {
        tmp = *prev + 1;
        prev = &tmp;
        bpf_map_update_elem(&count, &key, prev, BPF_ANY);
        return XDP_PASS;
    }
    tmp = 1;
    bpf_map_update_elem(&count, &key, &tmp, BPF_ANY);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
