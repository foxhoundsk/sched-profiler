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

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

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
/*
#define CPU_MASK (NPROC - 1)
struct {
    struct percpu_event cpu[NPROC];
} map = {};
*/

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
    struct lb_event e = {};

    e.type = DETACH_TASK_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_detach_one_task_end")
int dt_end(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = DETACH_TASK_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_detach_tasks_start")
int dts_start(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = DETACH_TASKS_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_detach_tasks_end")
int dts_end(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = DETACH_TASKS_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_cmt_s")
int cmt_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = CMT_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("raw_tp/sched_cmt_e")
int cmt_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = CMT_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

SEC("raw_tp/sched_thl_s")
int thl_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = THL_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_thl_e")
int thl_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = THL_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_ats_s")
int ats_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = ATS_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_ats_e")
int ats_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = ATS_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_socn_s")
int socn_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = SOCN_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_socn_e")
int socn_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = SOCN_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_fbq_s")
int fbq_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = FBQ_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("raw_tp/sched_fbq_e")
int fbq_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = FBQ_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("kprobe/find_busiest_group")
int fbg_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = FBG_S;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("kretprobe/find_busiest_group")
int fbg_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event e = {};

    e.type = FBG_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

SEC("kprobe/load_balance")
int do_lb_start(struct pt_regs *ctx)
{
    struct lb_event e = {};

    e.type = KP_LB;
    /* TODO figure out the flag, why duplicated callstack can co-exist */
    e.stack_id = bpf_get_stackid(ctx, &stackmap, 0);
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

/*
 * hook location:
 * https://elixir.bootlin.com/linux/v5.14/source/kernel/sched/fair.c#L9734
 */
SEC("raw_tp/sched_lb_end")
int BPF_PROG(lb_end)
{
    struct lb_event e = {};

    e.type = LB_E;
    e.ts = bpf_ktime_get_ns();
    bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

