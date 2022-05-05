#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> /* for system() */
#include <unistd.h>
#include <sys/sysinfo.h> /* for nproc TODO libbpf already has such API */
#include <bpf/bpf.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

/* cross-BPF pid accounting */
#include <unordered_map>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "trace_helpers.h"
#include "time_in_lb.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* TODO add this to cmdline option */
#define EVENT_THRES     5000

#define NR_ENTRY_PERCPU (1024 * 512)
#define EVENT_RINGBUF_SZ (1 << 16)

/* for full name of these timestamps, refer LB_FUNC_NAME */
struct prof_entry { /* profiling entry */
    long lb_s;
    long lb_e;
    long pne_s;
    long pne_e;
};

struct result {
    //struct prof_entry **cpu;
    enum lb_ev_type *cpu_last_state;
    int *nr_cpu_ev;
};

int hist_map[HIST_MAP_BUCKET_SZ] = {};
static volatile bool exiting = false;
static struct time_in_lb_bpf *skel;
static int nproc;
static struct result res;
static const char *func_name[] = {
    "run_rebalance_domains",
    "nohz_idle_balance",
    "_nohz_idle_balance",
    "rebalance_domains",
    "load_balance",
    "detach_tasks",
    "attach_tasks",
    "scheduler_tick",
    "task_tick_fair",
    "schedule",
    "__schedule",
    "pick_next_task",
};

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

static void sig_handler(int sig)
{
    fprintf(stderr, "\nSIGINT received, doing post-processing...\n");
    exiting = true;
}

static void sig_alarm_handler(int sig)
{
    fprintf(stderr, "\nalarm fired, doing post-processing...\n");
    exiting = true;
}

/* it's fine to truncate @delta, as it should not exceed 32-bit */
static void record_log2(int *hist_map, unsigned delta)
{
    int log = to_log2(delta);

    if (log >= HIST_MAP_BUCKET_SZ)
        log = HIST_MAP_BUCKET_SZ - 1;

    hist_map[log]++;
}

static inline void report_log2(int *hist_map)
{
    fprintf(stderr, "\nTIME(ns)\t HITCOUNT\n");
    for (unsigned long i = 0; i < HIST_MAP_BUCKET_SZ; i++) {
        fprintf(stderr, "%8lu -> %8lu: %5d\n", (unsigned long)1 << i, (unsigned long)1 << (i + 1), hist_map[i]);
    }
}
/*
static void report_result(void)
{
    int hist_map[HIST_MAP_BUCKET_SZ] = {};

    for (int c = 0; c < nproc; c++) {
        for (int i = 0; i < res.nr_cpu_ev[c]; i++) {
            struct prof_entry *pe = res.cpu[c] + i;
            long delta = pe->lb_e - pe->lb_s;

            record_log2(hist_map, delta);
            //printf("%ld\n", delta);


        }
    }

    report_log2(hist_map);
}
*/
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}
int d_pid[16] = {13, 25, 32, 39, 46, 53, 60, 67, 74, 81, 88, 95, 102, 109, 116, 123};
struct {
    long s;
    int cpu;
    bool sched_softirq_set;
} lat[16] = {};
static int count = 0;
static long jitter = 0;
static long jitter_min = 10000000000;
//static long tasks[2] = {};

/*
struct task_entry {
    long ts;
    bool migrated;
};*/

/* brought from the kernel */
#define TASK_RUNNING			0x0000

static std::unordered_map<int, long> tasks;

static int ringbuf_cb(void *ctx, void *data, size_t size)
{
    const struct lb_event *e = (struct lb_event*) data;

    switch (e->type) {
    case PNT_S:
long delta;
        /* prev task still in rq, record its awaiting time */
        if (likely(e->prev_pid && e->prev_state == TASK_RUNNING)) {
            printf("%ld cpu%2d %d\n", e->ts, e->cpu, e->prev_pid);
            tasks[e->prev_pid] = e->ts;
        }
        if (likely(e->pid)) {
            delta = e->ts - tasks[e->pid];
            if (unlikely(delta < 0))
                fprintf(stderr, "%ld cpu%d pid:%d\n", delta, e->cpu, e->pid);
            printf("%ld %d\n", delta, e->pid);
        }
        break;
    case AT_E:
        tasks[e->pid] = e->ts;
            printf("%ld cpu%2d %d\n", e->ts, e->cpu, e->pid);
        break;
    case TLB_S:
        tasks[e->pid] = e->ts;
            printf("%ld cpu%2d %d\n", e->ts, e->cpu, e->pid);
        break;
/*
    case AT_E:
        lat[e->cpu].s = e->ts;
        break;
    case TLB_S:
        printf("%ld\n", e->ts - lat[e->cpu].s);
        break;
*/
/* softirq lat.
    case S_CHED_S:
        if (e->pid != d_pid[e->cpu]) {
            printf("%ld CPU%2d, switch to pid:%d\n", e->ts, e->cpu, e->pid);
            break;
        }
        printf("%ld CPU%2d, switch to softirqd\n", e->ts, e->cpu);
        break;
    case TLB_S:
        lat[e->cpu].s = e->ts;
        //lat[e->cpu].sched_softirq_set = true;
        printf("%ld CPU%2d raised: %d\n", e->ts, e->cpu, e->pid);
        break;
    case DT_S:
        //if (!lat[e->cpu].sched_softirq_set)
          //  break;
        //lat[e->cpu].sched_softirq_set = false;
        break;
    case AT_S:
        //if (!lat[e->cpu].sched_softirq_set)
          //  break;
        //if (likely(e->pid != d_pid[e->cpu]))
          //  break;
        //lat[e->cpu].sched_softirq_set = false;
        if (e->pid == 7)
            printf("%ld CPU%2d SCHED_SOFTIRQ delta: %ld\n", e->ts, e->cpu, e->ts - lat[e->cpu].s);
        printf("%ld CPU%2d, enter SOFTIRQ: %d\n", e->ts, e->cpu, e->pid);
        break;
    case AT_E:
        printf("%ld CPU%2d, exit SOFTIRQ: %d\n", e->ts, e->cpu, e->pid);
        break;
*/
/* adaptive LB
    case PNT_S:
        if (e->pid == 889)
            tasks[0] = e->ts;
        else
            tasks[1] = e->ts;
        break;
    case RRD_S:
        long delta = e->ts - (e->pid == 889 ? tasks[0] : tasks[1]);
        if (delta < 1000000000 && delta > jitter)
            jitter = delta;
        if (delta < 1000000000 && delta < jitter)
            jitter_min = delta;

        break;
*/

/* adaptive LB
    case RRD_S:
        printf("%ld CPU%2d disable\n", e->ts, e->cpu);
        break;
    case PNT_S:
        printf("%ld CPU%2d enable\n", e->ts, e->cpu);
        break;
    case TTF_S:
        printf("%ld CPU%2d current avg_load: %ld, total_cap: %ld\n", e->ts, e->cpu, e->avg_load, e->total_cap);
        break;
*/

/*
    case TLB_S:
        printf("%ld CPU%2d, to cpu: %d,comm: %10s\n", e->ts, e->cpu, e->to_cpu, e->comm);
        break;
    case RD_S:
        lat[e->cpu].s = e->ts;
        lat[e->cpu].cpu = e->to_cpu;
        printf("%ld CPU%2d src_cpu: %d, pid: %d\n", e->ts, e->cpu, e->to_cpu, e->pid);
        break;
    case RD_E:
        printf("%ld CPU%2d b_group_t: %d i_group_t: %d\n", e->ts, e->cpu, e->pid, e->mtype);
        break;
    case NIB_E:
        printf("%ld CPU%2d SD_SHARE_CPUCAPACITY\n", e->ts, e->cpu);
        break;
    case RRD_S:
     //   if (abs(lat[e->cpu].cpu - e->to_cpu) != 8)
       //     break;
        //printf("%ld\n", e->ts - lat[e->cpu].s);
        if (e->pid == 927 || e->pid == 926)
            count++;
        break;
*/
/* trace LB softirq lat.
    case TLB_S:
        lat[e->cpu].s = e->ts;
        //lat[e->cpu].sched_softirq_set = true;
        break;
    case DT_S:
        if (!lat[e->cpu].sched_softirq_set)
            break;
        lat[e->cpu].sched_softirq_set = false;
        break;
    case AT_S:
        //if (!lat[e->cpu].sched_softirq_set)
          //  break;
        //if (likely(e->pid != d_pid[e->cpu]))
          //  break;
        printf("%ld\n", e->ts - lat[e->cpu].s);
        //lat[e->cpu].sched_softirq_set = false;
        break;
//-----------------------------
    case TLB_S:
        lat[e->cpu].s = e->ts;
        lat[e->cpu].sched_softirq_set = true;
        break;
    case DT_S:
//        printf("%ld\n", e->ts - lat[e->cpu].s);
        break;
    case AT_S:
        if (!lat[e->cpu].sched_softirq_set)
            break;
        if (likely(e->pid != d_pid[e->cpu]))
            break;
        assert(lat[e->cpu].s);
        printf("%ld\n", e->ts - lat[e->cpu].s);
        lat[e->cpu].sched_softirq_set = false;
        break;
*/
/*
        if (d_pid[cpu] != e->pid) return;
        //if (!lat[cpu].s) {exiting = 1; return;}
        //printf("%ld\n",  e->ts - lat[cpu].s);
        record_log2(hist_map, e->ts - lat[cpu].s);
        //lat[cpu].s = 0;
*/
    }

    return 0;
}

int main(int ac, char *av[])
{
    int err;
    struct ring_buffer *rb;

    //libbpf_set_print(libbpf_print_fn);

    /* alarm setup */
    if (ac == 2) {
        if (alarm(atoi(av[1]))) {
            fprintf(stderr, "Failed to set alarm\n");
            exit(-1);
        }
        signal(SIGALRM, sig_alarm_handler);
    }

    signal(SIGINT, sig_handler);

    bump_memlock_rlimit();

    nproc = get_nprocs_conf();

/*
    res.cpu = (prof_entry**) calloc(nproc, sizeof(struct prof_entry *));
    if (!res.cpu) {
        fprintf(stderr, "Failed to calloc for res.cpu\n");
        return -1;
    }
    for (int i = 0; i < nproc; i++) {
        res.cpu[i] = (prof_entry*) calloc(NR_ENTRY_PERCPU, sizeof(struct prof_entry));
        if (!res.cpu[i]) {
            fprintf(stderr, "Failed to calloc for res.cpu[%d]\n", i);
            return -1;
        }
    }
*/
    res.cpu_last_state = (lb_ev_type*) calloc(nproc, sizeof(enum lb_ev_type));
    res.nr_cpu_ev = (int*) calloc(nproc, sizeof(int));
    if (!res.cpu_last_state || !res.nr_cpu_ev) {
        /* TODO free mem */
        fprintf(stderr, "Failed to calloc for res\n");
        return -1;
    }

    /* init the state so that we save a if-condition in the hotpath */
    for (int i = 0; i < nproc; i++)
        res.cpu_last_state[i] = PNT_E;

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    /* unless otherwise necessary, this can shrink into time_in_lb_bpf__open_and_load */
    err = time_in_lb_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb1), ringbuf_cb, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    add_rb();

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }


    __atomic_store_n(&skel->bss->start_tracing, 1, __ATOMIC_RELEASE);

    while (!exiting) {
        err = ring_buffer__poll(rb, -1 /* timeout, ms */);
    }
    fprintf(stderr, "migration count: %d\n", count);
    fprintf(stderr, "jitter: %ld, jitter_min: %ld, jitter: %ld\n", jitter, jitter_min, jitter - jitter_min);
    report_log2(hist_map);

    /* to timely check BPF_STATS */
    system("../tools/bpftool prog list > bpftool_list_res");

    //report_result();
    fprintf(stderr, "BPF dropped %ld event(s)\n",
            __atomic_load_n(&skel->bss->dropped, __ATOMIC_ACQUIRE));

cleanup:
    time_in_lb_bpf__destroy(skel);
    ring_buffer__free(rb);
/*
    for (int i = 0; i < nproc; i++)
        free(res.cpu[i]);
    free(res.cpu);
*/
    free(res.cpu_last_state);
    free(res.nr_cpu_ev);

    return err < 0 ? -err : 0;

ringbuf_fail:
    time_in_lb_bpf__destroy(skel);
    ring_buffer__free(rb);
    free(res.cpu_last_state);
    free(res.nr_cpu_ev);
    fprintf(stderr, "Failed to call ring_buffer__add\n");
    return -1;
}

