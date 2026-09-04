/* Reference for integer signedness. Each case reads its operands from .bss
 * globals (so clang cannot constant-fold) and writes the result to a .bss
 * global (so the runtime proof is a `bpftool map dump`). The IR clang emits
 * for this file is the specification: zext vs sext on widening, udiv vs sdiv,
 * icmp ugt vs sgt, lshr vs ashr, and the trunc/zext pair that makes
 * u32 * u32 wrap at 32 bits. */
#define SEC(name) __attribute__((section(name), used))
typedef unsigned int __u32;
typedef int __s32;
typedef unsigned long long __u64;
typedef long long __s64;

/* inputs */
__u32 u32_max = 0xFFFFFFFFu;
__s32 s32_neg = -1;
__u32 u32_ten = 10;
__s32 s32_neg2 = -2;
__u64 u64_ten = 10;
__s64 s64_neg = -1;
__u32 u32_half = 0x80000000u;
__u32 u32_two = 2;

/* results */
__s64 widen_unsigned;   /* s64 = u32  -> 4294967295          zext      */
__u64 widen_signed;     /* u64 = s32  -> 0xffffffffffffffff  sext      */
__s32 reinterpret;      /* s32 = u32  -> -1                  no-op     */
__u32 mixed_div;        /* u32 / s32  -> 0                   udiv i32  */
__u64 unsigned_cmp;     /* u64 > s64  -> 0                   icmp ugt  */
__u64 narrow_wrap;      /* u32 * u32  -> 0 (wraps at 32)     trunc     */
__u32 shr_unsigned;     /* u32 >> 4   -> 0x0FFFFFFF          lshr      */
__s32 shr_signed;       /* s32 >> 4   -> -1                  ashr      */

SEC("tracepoint/raw_syscalls/sys_enter")
int prog(void *ctx)
{
    widen_unsigned = u32_max;
    widen_signed = s32_neg;
    reinterpret = u32_max;
    mixed_div = u32_ten / s32_neg2;
    unsigned_cmp = u64_ten > s64_neg;
    narrow_wrap = u32_half * u32_two;
    shr_unsigned = u32_max >> 4;
    shr_signed = s32_neg >> 4;
    return 0;
}

char _license[] SEC("license") = "GPL";
