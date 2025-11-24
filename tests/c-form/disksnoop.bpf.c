// disksnoop.bpf.c
// eBPF program (compile with: clang -O2 -g -target bpf -c disksnoop.bpf.c -o disksnoop.bpf.o)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, __u64);
	__uint(max_entries, 10240);
} start_map SEC(".maps");

/* kprobe: record start timestamp keyed by request pointer */
SEC("kprobe/blk_mq_start_request")
int trace_start(struct pt_regs *ctx)
{
	/* request * is first arg */
	__u64 reqp = (__u64)(ctx->di);
	__u64 ts = bpf_ktime_get_ns();

	bpf_map_update_elem(&start_map, &reqp, &ts, BPF_ANY);

//	/* optional debug:
	bpf_printk("start: req=%llu ts=%llu\n", reqp, ts);
//	*/
	return 0;
}

/* completion: compute latency and print data_len, cmd_flags, latency_us */
SEC("kprobe/blk_mq_end_request")
int trace_completion(struct pt_regs *ctx)
{
	__u64 reqp = (__u64)(ctx->di);
	__u64 *tsp;
	__u64 now_ns;
	__u64 delta_ns;
	__u64 delta_us = 0;
    bpf_printk("%lld", reqp);
	tsp = bpf_map_lookup_elem(&start_map, &reqp);
	if (!tsp)
		return 0;

	now_ns = bpf_ktime_get_ns();
	delta_ns = now_ns - *tsp;
	delta_us = delta_ns / 1000;

	/* read request fields using CO-RE; needs vmlinux.h/BTF */
	__u32 data_len = 0;
	__u32 cmd_flags = 0;

	/* __data_len is usually a 32/64-bit; use CORE read to be safe */
	data_len = ( __u32 ) BPF_CORE_READ((struct request *)reqp, __data_len);
	cmd_flags = ( __u32 ) BPF_CORE_READ((struct request *)reqp, cmd_flags);

	/* print: "<bytes> <flags_hex> <latency_us>" */
	bpf_printk("%u %x %llu\n", data_len, cmd_flags, delta_us);

	/* remove from map */
	bpf_map_delete_elem(&start_map, &reqp);

	return 0;
}
