#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "common.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* sched BPF requires this */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
/*
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 * 1024 * 1024); 
} rb SEC(".maps");
*/

/* CAUTION: PERCPU_ARRAY has size limitation of 32KB (per entry) */
/* https://elixir.bootlin.com/linux/v5.15/source/include/linux/percpu.h#L23 */
/* https://elixir.bootlin.com/linux/v5.15/source/mm/percpu.c#L1756 */

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");

/* for buffer overrun detection */
unsigned long dropped __attribute__((aligned(64))) = 0;

volatile bool start_tracing = false;

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

SEC("raw_tp/sched_pick_next_task_s")
int pnt_s(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = PNT_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_pick_next_task_e")
int pnt_e(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = PNT_E;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_pick_next_ent_s")
int pne_s(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = PNE_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_pick_next_ent_e")
int pne_e(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = PNE_E;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
/* *** ringbuf specific
SEC("raw_tp/sched_pick_next_task_s")
int pnt_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event *e;

    int cpu = bpf_get_smp_processor_id();
    if (CPU_OF_INTEREST != bpf_get_smp_processor_id())
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    
    e->type = PNT_S;
    e->ts = bpf_ktime_get_ns();
    e->cpu = cpu;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/sched_pick_next_task_e")
int urc_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event *e;

    int cpu = bpf_get_smp_processor_id();
    if (CPU_OF_INTEREST != bpf_get_smp_processor_id())
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = PNT_E;
    e->ts = bpf_ktime_get_ns();
    e->cpu = cpu;
    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_pick_next_ent_s")
int pne_s(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event *e;

    int cpu = bpf_get_smp_processor_id();
    if (CPU_OF_INTEREST != bpf_get_smp_processor_id())
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = PNE_S;
    e->ts = bpf_ktime_get_ns();
    e->cpu = cpu;
    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/sched_pick_next_ent_e")
int pne_e(struct bpf_raw_tracepoint_args *ctx)
{
    struct lb_event *e;

    int cpu = bpf_get_smp_processor_id();
    if (CPU_OF_INTEREST != bpf_get_smp_processor_id())
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = PNE_E;
    e->ts = bpf_ktime_get_ns();
    e->cpu = cpu;
    bpf_ringbuf_submit(e, 0);

    return 0;
}*/
