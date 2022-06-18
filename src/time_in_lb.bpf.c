#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <stdbool.h>

#include "common.h"

/* sched BPF requires this */
char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
/*
struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 1 * 1024 * 1024); 
} rb SEC(".maps");
*/

/*
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} pb SEC(".maps");
*/

/* turns out percpu array bpf map has no size limitation
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, LB_EVENT_SZ * 1000);
        __type(key, __u32);
        __type(value, struct lb_event);
} map SEC(".maps");
*/

/*
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, cputime_t);
} cpu_time SEC(".maps");
*/

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, sched_lat_t);
} sched_lat_map SEC(".maps");

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

#define TASK_RUNNING 0
/* cputime calculation
__always_inline
static int trace_enqueue(struct task_struct *t)
{
    u32 pid = t->pid;
    cputime_t *ptr;

    if (!pid)
        return 0;

    // create local storage at early stage, saving overhead in hotpath
    bpf_task_storage_get(&cpu_time, t, NULL,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);

    return 0;
}

__always_inline
static void trace_prev_task(struct task_struct *t)
{
    cputime_t *p;

    p = bpf_task_storage_get(&cpu_time, t, NULL, 0);

    if (!p)
            return;

    // sum cputime for this turn of execution
    p->sum += bpf_ktime_get_ns() - p->ts;
}

SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx[0];

    return trace_enqueue(p);
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
    // TP_PROTO(struct task_struct *p)
    struct task_struct *p = (struct task_struct *)ctx[0];

    return trace_enqueue(p);
}

SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
    // TP_PROTO(bool preempt, struct task_struct *prev,
    // 	    struct task_struct *next)

    struct task_struct *prev = (struct task_struct *)ctx[1];
    struct task_struct *next = (struct task_struct *)ctx[2];
    cputime_t *tls; // task local storage
    u64 delta_us;
    long state;
    u32 pid;

    // task is retired from cpu, calculate the cputime for this turn
    if (prev->pid)
        trace_prev_task(prev);

    pid = next->pid;

    // ignore idle task
    if (!pid)
        return 0;

    tls = bpf_task_storage_get(&cpu_time, next, 0, 0);
    if (!tls)
        return 0; // missed enqueue

    // timestamp for start of this turn
    tls->ts = bpf_ktime_get_ns();

    // reserved for future use
    //bpf_task_storage_delete(&start, next);
    return 0;
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
    struct task_struct *t = (struct task_struct *)ctx[0];
    int cpu = bpf_get_smp_processor_id();
    cputime_t *tls;

    tls = bpf_task_storage_get(&cpu_time, t, 0, 0);
    if (!tls)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    bpf_map_t *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    // sum for last turn
    tls->sum += bpf_ktime_get_ns() - tls->ts;

    bpf_probe_read(e->comm, TASK_COMM_LEN, t->comm);
    e->pid = t->pid;
    e->sum = tls->sum;

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/* wakeup overhead
SEC("kretprobe/__wake_up")
int BPF_KRETPROBE(prog1)
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
    e->type = N_IB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("kprobe/__wake_up")
int BPF_KPROBE(prog2, struct wait_queue_head *wq_head, unsigned int mode,
			int nr_exclusive, void *key)
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
    e->type = N_IB_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/softirq_raise")
int t12(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    if (ctx->args[0] != SCHED_SOFTIRQ)
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
    e->type = N_IB_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("kprobe/run_rebalance_domains")
int BPF_KPROBE(prog1, struct softirq_action *h)
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
    e->type = N_IB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_lb_chaining")
int t53(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = PNT_S;
    e->ccpu = ctx->args[0];
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
 //HRTICK delta expose

SEC("tp_btf/sched_hrtick")
int handle__sched_wakeup(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[1];
    int cpu = bpf_get_smp_processor_id();
    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;
    hrtick_map_t *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->delta = ctx[0];
    //bpf_probe_read(e->comm, TASK_COMM_LEN, p->comm);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

// sched lat.
/*
SEC("tp_btf/sched_switch")
int handle__sched_switch(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[2];
    struct task_struct *prev = (struct task_struct *)ctx[1];
    sched_lat_t *tls;

    if (prev->pid && prev->__state == TASK_RUNNING) {
        tls = bpf_task_storage_get(&sched_lat_map, prev, NULL, 0);
        if (tls)
            tls->ts = bpf_ktime_get_ns(); // start ts
    }

    tls = bpf_task_storage_get(&sched_lat_map, p, NULL, 0);
    if (!tls)
        return 0;

    tls->cnt++;
    tls->sum += bpf_ktime_get_ns() - tls->ts;

    return 0;
}
SEC("tp_btf/sched_wakeup")
int handle__sched_wakeup(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[0];
    sched_lat_t *tls;

    // record only newly created tasks, which are of interest to us
    tls = bpf_task_storage_get(&sched_lat_map, p, NULL, 0);
    if (!tls)
        return 0;

    tls->ts = bpf_ktime_get_ns();

    return 0;
}

SEC("tp_btf/sched_wakeup_new")
int handle__sched_wakeup_new(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[0];
    sched_lat_t *tls;

    tls = bpf_task_storage_get(&sched_lat_map, p, NULL,
                               BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tls)
        return 0;

    tls->ts = bpf_ktime_get_ns();

    return 0;
}

SEC("tp_btf/sched_process_exit")
int handle__sched_process_exit(u64 *ctx)
{
    struct task_struct *p = (struct task_struct *)ctx[0];
    int cpu = bpf_get_smp_processor_id();
    sched_lat_t *tls;

    tls = bpf_task_storage_get(&sched_lat_map, p, NULL, 0);
    if (!tls)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;
    sched_lat_map_t *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    bpf_probe_read(e->comm, TASK_COMM_LEN, p->comm);
    e->cnt = tls->cnt;
    e->sum = tls->sum;
    e->pid = p->pid;

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_switch")
int t53(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[2];
    struct task_struct *prev = ctx->args[1];


    int cpu = bpf_get_smp_processor_id();

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    bpf_probe_read(&e->pid, 4, &p->pid);
    bpf_probe_read(&e->prev_pid, 4, &prev->pid);
    bpf_probe_read(&e->prev_state, 4, &prev->__state);
    e->cpu = cpu;
    e->type = PNT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_wakeup")
int t52(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[0];

    int cpu = bpf_get_smp_processor_id();
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->pid = pid;
    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/sched_wakeup_new")
int t51(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[0];
    int cpu = bpf_get_smp_processor_id();
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->pid = pid;
    e->cpu = cpu;
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
//SEC("raw_tp/sched_wakeup_new")
//int t51(struct bpf_raw_tracepoint_args *ctx)

//SEC("kprobe/enqueue_task_fair")
/*
SEC("kprobe/dequeue_task_fair")
int BPF_KPROBE(prog1, struct rq *rq, struct task_struct *task, int flags)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = task;

    int cpu = bpf_get_smp_processor_id();
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

//    e->flags = flags;
    e->pid = pid;
    e->cpu = cpu;
    e->type = DT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}*/

/*
SEC("kretprobe/attach_task")
int t51(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = DT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("kprobe/attach_task")
int t54(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_detach_s")
int tb52(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = RD_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_detach_e")
int tb12(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = PNT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
// kthread execution time measurement

#define PF_KTHREAD		0x00200000
#define PF_WQ_WORKER		0x00000020
#define PF_KSWAPD		0x00020000
#define PF_IO_WORKER		0x00000010
#define IS_KTHREAD (PF_KTHREAD | PF_WQ_WORKER | PF_KSWAPD | PF_IO_WORKER)
/*
SEC("raw_tp/sched_same_task")
int tb52(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[0];
    void *kthread;
    unsigned int flags;
    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &p->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &p->flags);

    if (kthread && !(flags & IS_KTHREAD))
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

    bpf_probe_read(&e->pid, sizeof(p->pid), &p->pid);
    bpf_probe_read(e->comm, 10, p->comm);
    e->cpu = cpu;
    e->type = RD_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/* kthread execution time
SEC("raw_tp/sched_switch")
int t53(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[2];
    struct task_struct *prev = ctx->args[1];

    int send = 0;
    void *kthread;
    unsigned int flags;
    int pid;
    int ppid;

    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &p->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &p->flags);
    bpf_probe_read(&pid, 4, &p->pid);

    if ((flags & IS_KTHREAD) && pid)
        send |= 0x1;

    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &prev->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &prev->flags);
    bpf_probe_read(&ppid, 4, &prev->pid);

    if ((flags & IS_KTHREAD) && ppid)
        send |= 0x2;

    if (!send)
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

    if (send & 0x1) {
        bpf_probe_read(e->comm, 7, p->comm);
        e->pid = pid;
    } else
        e->pid = -1;

    if (send & 0x2) {
        bpf_probe_read(e->p_comm, 7, prev->comm);
        e->prev_pid = ppid;
    } else
        e->prev_pid = -1;

    e->cpu = cpu;
    e->type = PNT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/* paired with sched_switch, to measure sched lat. of kthread
SEC("raw_tp/sched_wakeup")
int t52(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[0];
    bool send = false;
    void *kthread;
    unsigned int flags;
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;
    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &p->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &p->flags);

    if (!kthread && (flags & IS_KTHREAD))
        send = true;

    if (!send)
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

    e->pid = pid;
    e->cpu = cpu;
    e->type = TLB_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/sched_wakeup_new")
int t51(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = ctx->args[0];
    bool send = false;
    void *kthread;
    unsigned int flags;
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;
    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &p->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &p->flags);

    if (!kthread && (flags & IS_KTHREAD))
        send = true;

    if (!send)
        return 0;

    int cpu = bpf_get_smp_processor_id();
    int pid;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->pid = pid;
    e->cpu = cpu;
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
//SEC("raw_tp/sched_wakeup_new")
//int t51(struct bpf_raw_tracepoint_args *ctx)

//SEC("kprobe/enqueue_task_fair")
SEC("kprobe/dequeue_task_fair")
int BPF_KPROBE(prog1, struct rq *rq, struct task_struct *task, int flags)
{
    if (unlikely(!start_tracing))
        return 0;

    struct task_struct *p = task;
    bool send = false;
    void *kthread;
    unsigned int flags;
    int pid;

    bpf_probe_read(&pid, 4, &p->pid);
    if (!pid)
        return 0;
    bpf_probe_read(&kthread, sizeof(p->set_child_tid), &p->set_child_tid);
    bpf_probe_read(&flags, sizeof(p->flags), &p->flags);

    if (!kthread && (flags & IS_KTHREAD))
        send = true;

    if (!send)
        return 0;


    int cpu = bpf_get_smp_processor_id();
    int pid;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->pid = pid;
    e->cpu = cpu;
    e->type = DT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_lb_chaining")
int t52(struct bpf_raw_tracepoint_args *ctx)
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
    e->pid = ctx->args[0];
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("kretprobe/load_balance")
int t52(struct bpf_raw_tracepoint_args *ctx)
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
SEC("kprobe/load_balance")
int t51(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_lb_chaining")
int t52(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = N_IB_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/softirq_entry")
int t22(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

//    if (ctx->args[0] != SCHED_SOFTIRQ)
//        return 0;

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
    e->pid = ctx->args[0];
    e->type = AT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("raw_tp/softirq_exit")
int t52(struct bpf_raw_tracepoint_args *ctx)
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
    e->pid = ctx->args[0];
    e->type = AT_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_switch")
int tba15(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    int pid;
    struct task_struct *p = ctx->args[2];

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = S_CHED_S;
    e->cpu = cpu;
    bpf_probe_read(&e->pid, 4, &p->pid);
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_e")
int t221(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = DT_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}*/
/* adaptive LB
SEC("raw_tp/sched_wakeup")
int tb15(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    int pid;
    struct task_struct *p = ctx->args[0];
    bpf_probe_read(&pid, 4, &p->pid);
    if (pid != 889 && pid != 890)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = PNT_S;
    e->pid = pid;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_switch")
int ta15(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    int pid;
    struct task_struct *p = ctx->args[2];
    bpf_probe_read(&pid, 4, &p->pid);
    if (pid != 889 && pid != 890)
        return 0;

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->type = RRD_S;
    e->cpu = cpu;
    e->pid = pid;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}*/
/*
SEC("raw_tp/sched_key_enable")
int tb15(struct bpf_raw_tracepoint_args *ctx)
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

    e->type = PNT_S;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_key_disable")
int ta15(struct bpf_raw_tracepoint_args *ctx)
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

    e->type = RRD_S;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/

/*
SEC("raw_tp/sched_enqueue_task_fair")
int b5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    struct task_struct *p = ctx->args[0];

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->to_cpu = ctx->args[1];
    bpf_probe_read(e->comm, 10, p->comm);
    e->type = TLB_S;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_migrate_type")
int t15(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    struct task_struct *p = ctx->args[0];

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->to_cpu = ctx->args[0];
    e->pid = ctx->args[1];
    e->type = RD_S;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
SEC("raw_tp/sched_attached")
int ta15(struct bpf_raw_tracepoint_args *ctx)
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
    e->pid = ctx->args[0];
    e->to_cpu = ctx->args[1];
    e->type = RRD_S;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}
*/
/*
SEC("raw_tp/sched_imb")
int z5(struct bpf_raw_tracepoint_args *ctx)
{
    if (unlikely(!start_tracing))
        return 0;

    int cpu = bpf_get_smp_processor_id();
    struct task_struct *p = ctx->args[0];

    struct bpf_map *rb = bpf_map_lookup_elem(&map_array, &cpu);
    if (!rb)
        return 0;

    struct lb_event *e = bpf_ringbuf_reserve(rb, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&dropped, 1);
        return 0;
    }

    e->pid = ctx->args[0];
    e->mtype = ctx->args[1];
    e->type = RD_E;
    e->cpu = cpu;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}*/
/*
SEC("raw_tp/sched_share")
int tq15(struct bpf_raw_tracepoint_args *ctx)
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
    e->type = NIB_E;
    e->ts = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);

    return 0;
}*/
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
