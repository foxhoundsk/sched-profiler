#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> /* system() */
#include <unistd.h>
#include <sys/sysinfo.h> /* nproc TODO libbpf already has such API */
#include <bpf/bpf.h>
#include <string.h>

#include "common.h"
#include "trace_helpers.h"
#include "time_in_lb.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* TODO add this to cmdline option */
#define EVENT_THRES     10000

struct result {
    struct percpu_event cpu[NPROC];
};
/*
struct result {
    lb_event_t enq[LB_EVENT_SZ / 2];
    lb_event_t deq[LB_EVENT_SZ / 2];
    unsigned long stack_id[LB_EVENT_SZ / 2];
//    struct lb_iter_cnt lb_iter[LB_EVENT_SZ / 2];
    int nr_enq_ev;
    int nr_deq_ev;
};*/

struct max_ev {
    long t1;
    long t2; /* the latter ts */
    long delta;
    unsigned long stack_id;
    struct lb_iter_cnt lb_iter;
};

static volatile bool exiting = false;
static struct time_in_lb_bpf *skel;
static int nproc;
static unsigned int *percpu_idx;

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

static void print_ksym(unsigned long addr)
{
        struct ksym *sym;
        bool is_target;

        if (likely(!addr))
                return;
        sym = ksym_search(addr);
        if (!sym) {
                fprintf(stderr, "ksym not found. Is kallsyms loaded?\n");
                return;
        }

        /* 6 should do the trick */
        is_target = !strncmp(sym->name, "load_balance", 6);

        fprintf(stderr, "%s%s", sym->name, is_target ? " " : "\n");
}

static void print_stacktrace(int fd, unsigned long id)
{
    unsigned long ip[PERF_MAX_STACK_DEPTH] = {};

    if (bpf_map_lookup_elem(fd, &id, ip) != 0) {
        fprintf(stderr, "Failed to find the stacktrace. stack_id:%lu\n", id);
        perror("stacktrace");
    } else {
        for (int i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
            print_ksym(ip[i]);
    }
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
    for (int i = 0; i < HIST_MAP_BUCKET_SZ; i++) {
        fprintf(stderr, "%5d -> %5d: %5d\n", 1 << i, 1 << (i + 1), hist_map[i]);
    }
}

enum {
    DETACH_TASKS,
    DETACH_TASK,
    LB_FUNC_MAX,
};
static const char *LB_FUNC_NAME[] = {
    [DETACH_TASKS] = "detach_tasks",
    [DETACH_TASK] = "detach_task",
};

static void report_result(void)
{
    int orphan_event = 0, tt_enq = 0, tt_deq = 0, stackmap_fd,
        hist_map[HIST_MAP_BUCKET_SZ] = {}, max_mb = 0;

    /* stackmap collision count */
    int stackmap_cc = 0;
    struct result *res;
    struct max_ev max = {};

    stackmap_fd = bpf_map__fd(skel->maps.stackmap);
    if (stackmap_fd < 0) {
        fprintf(stderr, "Failed to get stackmap fd\n");
        return;
    }

    res = calloc(nproc, sizeof(*res));
    if (!res) {
        fprintf(stderr, "Failed to malloc\n");
        return;
    }

    for (int c = 0; c < nproc; c++) {
        for (int idx = 0; idx < percpu_idx[c]; idx++) {
            if (unlikely(__atomic_load_n(&skel->bss->map.cpu[c].ev[idx].lb_s,
                         __ATOMIC_ACQUIRE) == 0))
                continue; /* or we can simply start from 5th entry or so to prevent incomplete event */

            /*
             * we've already waited for 1 sec, store buffer and invalid queue
             * should have already flushed.
             *
             * TODO USE ASSERT TO CHECK IF WE DIDNT USE MEM BARRIER WELL.
             */
            res->cpu[c].ev[idx].lb_s = skel->bss->map.cpu[c].ev[idx].lb_s;
            res->cpu[c].ev[idx].lb_e = skel->bss->map.cpu[c].ev[idx].lb_e;
            res->cpu[c].ev[idx].dts_s = skel->bss->map.cpu[c].ev[idx].dts_s;
            res->cpu[c].ev[idx].dts_e = skel->bss->map.cpu[c].ev[idx].dts_e;

            res->cpu[c].ev[idx].dt_idx = skel->bss->map.cpu[c].ev[idx].dt_idx;
            for (int e = 0; e < skel->bss->map.cpu[c].ev[idx].dt_idx; e++) {
                res->cpu[c].ev[idx].dt[e].s = skel->bss->map.cpu[c].ev[idx].dt[e].s;
                res->cpu[c].ev[idx].dt[e].e = skel->bss->map.cpu[c].ev[idx].dt[e].e;
            }

            res->cpu[c].stack_id[idx] = __atomic_load_n(
                                        &skel->bss->map.cpu[c].stack_id[idx],
                                        __ATOMIC_ACQUIRE);
        }
    }

    for (int c = 0; c < nproc; c++) {
        for (int i = 0; i < percpu_idx[c]; i++) {
            int indent = 1;
            long delta = res->cpu[c].ev[i].lb_e - res->cpu[c].ev[i].lb_s;
            if (res->cpu[c].stack_id[i] == -EEXIST) {
                stackmap_cc++;
                continue;
            }

            record_log2(hist_map, delta);

            if (delta < EVENT_THRES)
                continue;

            print_stacktrace(stackmap_fd, res->cpu[c].stack_id[i]);
            fprintf(stderr, "-> %ld ns\n", delta);
            
            for (int z = 0; z < LB_FUNC_MAX; z++, indent++) {
                switch (z) {
                case DETACH_TASKS:
                    for (int v = 0; v < indent; v++)
                        fprintf(stderr, "  ");

                    delta = res->cpu[c].ev[i].dts_e - res->cpu[c].ev[i].dts_s;
                    if (!delta)
                        goto out;
                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[DETACH_TASKS],
                            delta);
                    break;
                case DETACH_TASK:
                    for (int w = 0; w < res->cpu[c].ev[i].dt_idx; w++) {
                        for (int v = 0; v < indent; v++)
                            fprintf(stderr, "  ");

                        delta = res->cpu[c].ev[i].dt[w].e - res->cpu[c].ev[i].dt[w].s;

                        if (!delta)
                            goto out;
                        fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[DETACH_TASK],
                                delta);
                    }
                    break;
                }
            }
out:
            fprintf(stderr, "\r----------\n");
        }
    }

    /*
     * for minimizing measurement overhead, some metrics are
     * disabled for normal compilation. I.e., mertics that
     * enclosed by the DEBUG flag.
     */
#ifdef DEBUG
    fprintf(stderr, "dropped %ld event(s)\n",
            __atomic_load_n(&skel->bss->dropped, __ATOMIC_RELAXED));
#endif/*
    puts("");
    for (int c = 0; c < nproc; c++) {
        fprintf(stderr, "CPU#%-2d has %4d LB_START events, %4d LB_END "
                "events, total of %4d\n",
                c, res[c].nr_enq_ev, res[c].nr_deq_ev,
                res[c].nr_enq_ev + res[c].nr_deq_ev);
    }
    fprintf(stderr, "\ncaptured %d event(s)\nLB_START event: %d, "
            "LB_END event: %d\norphan event: %d\n",
            tt_enq + tt_deq,
            tt_enq,
            tt_deq,
            orphan_event);
    if (stackmap_cc)
        fprintf(stderr, "Stackmap collision occured %d time%s, plz consider "
                "increase the map size!\n", stackmap_cc, stackmap_cc > 1 ? "s"
                : "");

//     report max event 
    fprintf(stderr, "\n----------------\n");
    fprintf(stderr, "the max event:\n\n");
    fprintf(stderr, "delta: %f ms, start: %ld, end: %ld\n",
            max.delta / 1000000., max.t1, max.t2);
    fprintf(stderr, "stacktrace:\n");
    print_stacktrace(stackmap_fd, max.stack_id);
    fprintf(stderr, "----------------\n");
*/

    report_log2(hist_map);
    //fprintf(stderr, "max_redo: %d\n", max_mb);
    free(res);
}

/*
 * Check if the desired amount of event has reached, `target_ev` would be
 * LB_EVENT_SZ if not specified at cmdline.
 */
static bool should_stop(int target_ev)
{
    /* once all of the CPUs reached the amount, stop profiling */
    for (int c = 0; c < nproc; c++) {
        /* paired with __sync_fetch_and_add() in the BPF prog */
        if (__atomic_load_n(&skel->bss->map.cpu[c].idx, __ATOMIC_ACQUIRE) ==
            target_ev) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}

int main(int ac, char *av[])
{
    int err;
    unsigned int target_ev = LB_EVENT_SZ;

 //   libbpf_set_print(libbpf_print_fn);

    if (ac == 2)
        target_ev = atoi(av[1]);

    if (load_kallsyms()) {
        fprintf(stderr, "failed to process /proc/kallsyms\n");
        return -1;
    }

    nproc = get_nprocs_conf();

    percpu_idx = malloc(nproc * sizeof(unsigned int));
    if (!percpu_idx) {
        fprintf(stderr, "Failed to malloc\n");
        return -1;
    }
    /* then we exchange with the one in the BPF prog to stop the exec of BPF */
    for (int i = 0; i < nproc; i++)
        percpu_idx[i] = LB_EVENT_SZ;

    bump_memlock_rlimit();

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    err = time_in_lb_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }

    /* walk the buffer first to reduce page faults in the sched */
    for (int i = 0; i < nproc; i++) {
        skel->bss->map.cpu[i].idx = 0;
        for (int z = 0; z < LB_EVENT_SZ; z++) {
            skel->bss->map.cpu[i].stack_id[z] = 0;
        }
        for (int z = 0; z < LB_EVENT_SZ; z++) {
            skel->bss->map.cpu[i].ev[z] = (struct event) {};
        }/*
        for (int z = 0; z < LB_EVENT_SZ; z++) {
            skel->bss->map.cpu[i].lb_iter[z] = (struct lb_iter_cnt)
                                                  {.redo = 0, .mb = 0};
        }*/
    }

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
//int tt;
    while (!exiting /*&& !should_stop(target_ev)*/) {
/*
        if (-1 < (tt=__atomic_load_n(&skel->data->tf, __ATOMIC_ACQUIRE)))
            fprintf(stderr, "PASSED: %d\n", tt);
        else
            fprintf(stderr, "havent PASSED: %d\n", tt);
  */          
        sleep(5);
    }

    /* to check BPF_STATS accurately */
    system("../tools/bpftool prog list > bpftool_list_res");

    /*
     * store the current indexes before we sleep for 1 sec, then we guarantee
     * that the event we see later won't be in the middle of an update.
     */
    for (int i = 0; i < nproc; i++)
        /* paired with __sync_fetch_and_add() in the BPF prog */
        percpu_idx[i] = __atomic_exchange_n(&skel->bss->map.cpu[i].idx,
                                            LB_EVENT_SZ,
                                            __ATOMIC_ACQUIRE);
    sleep(1);

    report_result();

cleanup:
    time_in_lb_bpf__destroy(skel);
    free(percpu_idx);

    return err < 0 ? -err : 0;
}

