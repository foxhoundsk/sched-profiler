#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "common.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define KERN_STACKID_FLAGS (0 | BPF_F_REUSE_STACKID)
/* sched BPF requires this */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
/*
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 2 * 1024 * 1024  2MB ); 
} rb SEC(".maps");
*/

/* CAUTION: PERCPU_ARRAY has size limitation of 32KB (per entry) */
/* https://elixir.bootlin.com/linux/v5.15/source/include/linux/percpu.h#L23 */
/* https://elixir.bootlin.com/linux/v5.15/source/mm/percpu.c#L1756 */

struct {
        __uint(type, BPF_MAP_TYPE_STACK_TRACE);
        __uint(key_size, sizeof(u32));
        __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
        __uint(max_entries, 50000);
} stackmap SEC(".maps");

#ifdef DEBUG
/*
 * @dropped
 *
 * monitor whether the backlog is big enough. (BPF ringbuf uses a lightweight.
 * spinlock internally, can we keep up with this in sched code path?)
 *
 * btw, should we align up to 128 bytes instead of 64 bytes to prevent
 * false-sharing?
 */
unsigned long dropped __attribute__((aligned(128))) = 0;
#endif

/*
 * this should be nproc of target machine, however, IIUC, this is not
 * dynamically adjustable.
 */
#define CPU_MASK (NPROC - 1)
struct {
    struct percpu_event cpu[NPROC];
} map = {};

// TODO move this into the header
struct sched_switch_args {
	unsigned long long pad;
	char prev_comm[16];
	int prev_pid;
	int prev_prio;
	long long prev_state;
	char next_comm[16];
	int next_pid;
	int next_prio;
};
/*
SEC("tracepoint/sched/sched_switch")
int do_lb_end(struct sched_switch_args *ctx)
{
    int pid = ctx->prev_pid;

    __u32 cpu = bpf_get_smp_processor_id();
    if (__sync_fetch_and_add(&tf, 0) == -1)
        __sync_fetch_and_add(&tf, pid);
    return 0;
}
*/

SEC("raw_tp/sched_detach_one_task_start")
int dt_start(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;
    __u32 dt_idx;

    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;

    dt_idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dt_idx, 0);
    if (unlikely(dt_idx >= MAX_NR_DETACH_TASK))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dt[dt_idx].s,
                         bpf_ktime_get_ns());
    
    return 0;
}

SEC("raw_tp/sched_detach_one_task_end")
int dt_end(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;
    __u32 dt_idx;

    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;

    dt_idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dt_idx, 0);
    if (unlikely(dt_idx >= MAX_NR_DETACH_TASK))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dt[dt_idx].e,
                         bpf_ktime_get_ns());

    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dt_idx, 1);
    return 0;
}

SEC("raw_tp/sched_detach_tasks_start")
int dts_start(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;

    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dts_s,
                         bpf_ktime_get_ns());
    return 0;
}

SEC("raw_tp/sched_detach_tasks_end")
int dts_end(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;

    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].dts_e,
                         bpf_ktime_get_ns());
    return 0;
}

SEC("kprobe/load_balance")
int do_lb_start(struct pt_regs *ctx)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;
    __u64 key;

    /* guarantee we see update from other CPUs */
    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);

    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;
    /*
     * If the stack_id slot has already used and we meet it again, it means that
     * the other BPF progs haven't started the execution yet, in which case
     * *idx* would not get updated. This could happen at early of the profiling,
     * since the insertion of BPF progs is not synchronous.
     *
     * In such case, we reset the slot.
     *
     * In case of that lb_end starts prior to lb_start, we don't need to worry
     * about that we may have corrupted event logged, as the userspace will then
     * detect that the time delta of this event is negative, which will then
     * discard this event.  And the reason why we can use direct assignment here
     * is that such scenario would only happen at early stage, thus we would
     * only have corrupt result if we stop the profiling early, which would
     * typically not performed by a normal profiling operation.
     */
    if (unlikely(map.cpu[cpu & CPU_MASK].stack_id[idx] != 0))
        map.cpu[cpu & CPU_MASK].stack_id[idx] = 0;

    key = bpf_get_stackid(ctx, &stackmap, 0);
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].stack_id[idx], key);

    return 0;
}

/*
 * hook location:
 * https://elixir.bootlin.com/linux/v5.14/source/kernel/sched/fair.c#L9973
 */
SEC("sched/cfs_trigger_load_balance_start")
int BPF_PROG(lb_start)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;

    /* guarantee we see updates from other CPUs */
    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].lb_s,
                         bpf_ktime_get_ns());
    return 0;
}

/*
 * hook location:
 * https://elixir.bootlin.com/linux/v5.14/source/kernel/sched/fair.c#L9734
 */
SEC("sched/cfs_trigger_load_balance_end")
int BPF_PROG(lb_end)
{
    __u32 cpu = bpf_get_smp_processor_id();
    __u32 idx;

    /* guarantee we see updates from other CPUs */
    idx = __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 0);
    if (unlikely(idx >= LB_EVENT_SZ))
        return 0;
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].ev[idx].lb_e,
                         bpf_ktime_get_ns());
    __sync_fetch_and_add(&map.cpu[cpu & CPU_MASK].idx, 1);

    return 0;
}

