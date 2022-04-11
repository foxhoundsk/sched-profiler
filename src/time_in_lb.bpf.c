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

/*
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");
*/

struct ringbuf_map {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 2 * 1024 * 1024 /* 2MB */); 
} rb1 SEC(".maps"),
    rb2 SEC(".maps"),
    rb3 SEC(".maps"),
    rb4 SEC(".maps"),
    rb5 SEC(".maps"),
    rb6 SEC(".maps"),
    rb7 SEC(".maps"),
    rb8 SEC(".maps"),
    rb9 SEC(".maps"),
    rb10 SEC(".maps"),
    rb11 SEC(".maps"),
    rb12 SEC(".maps"),
    rb13 SEC(".maps"),
    rb14 SEC(".maps"),
    rb15 SEC(".maps"),
    rb16 SEC(".maps");

struct map_array {
        __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
        __uint(max_entries, 16);
        __uint(key_size, sizeof(int));
        __uint(value_size, sizeof(int));
        __array(values, struct ringbuf_map);
} map_array SEC(".maps") = {
        .values = { &rb1,&rb2,&rb3,&rb4,&rb5,&rb6,&rb7,&rb8,&rb9,&rb10,&rb11,&rb12,&rb13,&rb14,&rb15,&rb16, },
};

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

SEC("raw_tp/sched_run_rebalance_domains_s")
int w6(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_run_rebalance_domains_e")
int w5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched__nohz_idle_balance_s")
int w2(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched__nohz_idle_balance_e")
int w1(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_rebalance_domains_s")
int a9(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_rebalance_domains_e")
int a8(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_load_balance_s")
int a7(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_load_balance_e")
int a6(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_detach_tasks_s")
int a5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_detach_tasks_e")
int a4(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_attach_tasks_s")
int a3(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_attach_tasks_e")
int a2(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
/* FIXME: presently, we call the Perfetto API once a BPF event is sent to
 * userspace, which is fine for most cases. However, async event (e.g.
 * trigger_load_balance()) would break the event recording of Perfetto.
 * Specifically, for example, an epilogue event of sched_scheduler_tick_e
 * would accidentally be treated as the epilogue event of
 * trigger_load_balance's because it's async call, which didn't end as the
 * function ends.
 *
 * A possible fix would be record the event during the profiling, and do
 * post-processing afterward.
 */
/*
SEC("raw_tp/sched_scheduler_tick_s")
int a1(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;
    struct lb_event e = {};
    e.type = ST_S;
    e.ts = bpf_ktime_get_ns();
    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);
    return 0;
}
SEC("raw_tp/sched_scheduler_tick_e")
int q7(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;
    struct lb_event e = {};
    e.type = ST_E;
    e.ts = bpf_ktime_get_ns();
    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);
    return 0;
}*/
SEC("raw_tp/sched_task_tick_fair_s")
int q6(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_task_tick_fair_e")
int q5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched___schedule_s")
int q2(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched___schedule_e")
int q1(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_pick_next_task_s")
int pnt_s(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_pick_next_task_e")
int pnt_e(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/sched_lb_softirq_s")
int t5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
SEC("raw_tp/sched_imb")
int t8(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = RD_E;
    e.pid = ctx->args[0];
    e.mtype = ctx->args[1];
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_migrate_type")
int t2(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.mtype = ctx->args[0];
    e.pid = ctx->args[1];
    e.type = TLB_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_detach_one_task")
int t12(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.pid = ctx->args[0];
    e.type = TTF_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_c")
int t22(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.pid = ctx->args[0];
    e.mtype = ctx->args[1];
    e.type = AT_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_wakeup")
int v22(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx->args[0];

    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    bpf_probe_read(&e.pid, 4, &p->pid);
    bpf_probe_read(&e.mtype, 4, &p->cpu);
    bpf_probe_read(&e.dum, 4, &p->on_cpu);
    e.type = DT_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
*/
/*
SEC("raw_tp/sched_s")
int t12(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_switch")
int t32(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *p = ctx->args[2];

    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    bpf_probe_read(&e.pid, 4, &p->pid);
    e.type = AT_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_e")
int t22(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = DT_S;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
*/
/*
SEC("raw_tp/sched_a")
int tq(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = 1000;
    e.pid = ctx->args[0];
    e.mtype = ctx->args[1];
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_b")
int atq(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = 1001;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_c")
int btq(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.pid = ctx->args[0];
    e.type = 1002;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
SEC("raw_tp/sched_d")
int tqg(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = 1003;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}
*/
/*
SEC("raw_tp/sched_newidle")
int otq(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct lb_event e = {};

    e.type = 1004;
    e.ts = bpf_ktime_get_ns();

    if (bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, &e, sizeof(e)))
        __sync_fetch_and_add(&dropped, 1);

    return 0;
}*/
