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
} lat[16] = {};
static int ringbuf_cb(void *ctx, void *data, size_t size)
{
    const struct lb_event *e = (struct lb_event*) data;

    switch (e->type) {
    case TLB_S:
        lat[e->cpu].s = e->ts;
        break;
    case AT_S:
/*
        if (d_pid[cpu] != e->pid) return;
        //if (!lat[cpu].s) {exiting = 1; return;}
        //printf("%ld\n",  e->ts - lat[cpu].s);
        record_log2(hist_map, e->ts - lat[cpu].s);
        //lat[cpu].s = 0;
*/
        break;
    }

    return 0;
}

int main(int ac, char *av[])
{
    int err;
    struct ring_buffer *rb;

    //libbpf_set_print(libbpf_print_fn);

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
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb2),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb3),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb4),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb5),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb6),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb7),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb8),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb9),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb10),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb11),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb12),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb13),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb14),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb15),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;
    err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb16),
                              ringbuf_cb, NULL);
    if (err) goto ringbuf_fail;

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    __atomic_store_n(&skel->bss->start_tracing, 1, __ATOMIC_RELEASE);

    while (!exiting) {
        err = ring_buffer__poll(rb, -1 /* timeout, ms */);
    }
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

