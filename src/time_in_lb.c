#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> /* system() */
#include <unistd.h>
#include <sys/sysinfo.h> /* nproc TODO libbpf already has such API */
#include <bpf/bpf.h>
#include <string.h>
#include <assert.h>

#include "common.h"
#include "trace_helpers.h"
#include "time_in_lb.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* TODO add this to cmdline option */
#define EVENT_THRES     5000

/* detach_tasks can detach at most 32 tasks per call */
#define MAX_NR_MIGRATION 32

/*
 * detach_tasks may run multiple times in a single load balance, lets assume it's 2 for now.
 */
#define MAX_NR_DTS_ITER 2
#define MAX_NR_ATS_ITER 2
#define MAX_NR_SOCN_ITER 2
#define MAX_NR_FBQ_ITER 2
#define MAX_NR_FBG_ITER 2
#define NR_ENTRY_PERCPU 16384

struct prof_entry { /* profiling entry */
    long stack_id;
    long lb_s;
    long lb_e;
    struct {
        long s; /* detach tasks start */
        long e;
        struct {
            long s;
            long e;
            long crl_s; /* cfs_rq_last_update_time */
            long crl_e;
            long stc_e;
        } dt[MAX_NR_MIGRATION];
        int nr_dt; /* detach_task */

        struct {
            long s;
            long e;
        } cmt[MAX_NR_MIGRATION];
        int nr_cmt; /* can_migrate_task */

        struct {
            long s;
            long e;
        } thl[MAX_NR_MIGRATION];
        int nr_thl;
    } dts[MAX_NR_DTS_ITER]; /* detach_tasks */
    int nr_dts;

    struct {
        long s;
        long e;
    } ats[MAX_NR_ATS_ITER]; /* attach_tasks */
    int nr_ats;

    struct {
        long s;
        long e;
    } socn[MAX_NR_SOCN_ITER];
    int nr_socn;

    struct {
        long s;
        long e;
    } fbg[MAX_NR_FBG_ITER];
    int nr_fbg;

    struct {
        long s;
        long e;
    } fbq[MAX_NR_FBQ_ITER];
    int nr_fbq;
};

struct result {
    struct prof_entry **cpu;
    enum lb_ev_type *cpu_last_state;
    int *nr_cpu_ev;
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
static struct result res;

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

enum lb_func_idx {
    DETACH_TASKS,
    DETACH_TASK,
    CMT,
    THL,
    ATS,
    SOCN,
    FBG,
    FBQ,
    CRLUT,
    STC,
    LB_FUNC_MAX,
};
static const char *LB_FUNC_NAME[] = {
    [DETACH_TASKS] = "detach_tasks",
    [DETACH_TASK]  = "detach_task",
    [CMT]          = "can_mirgate_task",
    [THL]          = "task_h_load",
    [ATS]          = "attach_tasks",
    [SOCN]         = "stop_one_cpu_nowait",
    [FBG]          = "find_busiest_group",
    [FBQ]          = "find_busiest_queue",
    [CRLUT]        = "deactivate_task", /* reusing tracepoint */
    [STC]          = "set_task_cpu", /* reusing tracepoint */
};

static void report_result(void)
{
    int orphan_event = 0, tt_enq = 0, tt_deq = 0, stackmap_fd,
        hist_map[HIST_MAP_BUCKET_SZ] = {}, maxl = 0, maxI, mdelta, maxl2 = 0, maxI2, mdelta2;

    /* stackmap collision count */
    int stackmap_cc = 0;
    struct max_ev max = {};

    stackmap_fd = bpf_map__fd(skel->maps.stackmap);
    if (stackmap_fd < 0) {
        fprintf(stderr, "Failed to get stackmap fd\n");
        return;
    }

    for (int c = 0; c < nproc; c++) {
        for (int i = 0; i < res.nr_cpu_ev[c]; i++) {
            struct prof_entry *pe = res.cpu[c] + i;
            long delta = pe->lb_e - pe->lb_s;
            if (pe->stack_id == -EEXIST) {
                stackmap_cc++;
                continue;
            }

            record_log2(hist_map, delta);

//            printf("%ld\n", delta); for log into the log file (redirect stdout to file)

            if (delta < EVENT_THRES)
                continue;

            fprintf(stderr, "CPU%d, entry no.%d, stack_id: %lu\n", c, i, pe->stack_id);

            print_stacktrace(stackmap_fd, pe->stack_id);
            fprintf(stderr, "-> %ld ns\n", delta);

            /* find_busiest_group call site */
            for (int z = 0; z < pe->nr_fbg; z++) {
                delta = pe->fbg[z].e - pe->fbg[z].s;

                for (int v = 0; v < 1; v++) /* TODO if we still using this, macro it */
                    fprintf(stderr, "  ");

                fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[FBG], delta);
            }
            /* find_busiest_queue call site */
            for (int z = 0; z < pe->nr_fbq; z++) {
                delta = pe->fbq[z].e - pe->fbq[z].s;

                for (int v = 0; v < 1; v++) /* TODO if we still using this, macro it */
                    fprintf(stderr, "  ");

                fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[FBQ], delta);
            }

            /* detach_tasks call site */
            for (int z = 0; z < pe->nr_dts; z++) {
                int sum = 0;
                delta = pe->dts[z].e - pe->dts[z].s;

                for (int v = 0; v < 1; v++) /* TODO if we still using this, macro it */
                    fprintf(stderr, "  ");

                fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[DETACH_TASKS],
                        delta);

                for (int d = 0; d < pe->dts[z].nr_cmt; d++) {
                    delta = pe->dts[z].cmt[d].e - pe->dts[z].cmt[d].s;

                    sum += (int) delta;
                    for (int v = 0; v < 2; v++)
                        fprintf(stderr, "  ");

                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[CMT],
                            delta);
                }
                if (sum) {
                    fprintf(stderr, "[%s called %d times, elapsed: %d ns]\n",
                            LB_FUNC_NAME[CMT], pe->dts[z].nr_cmt, sum);
                    sum = 0;
                }

                for (int d = 0; d < pe->dts[z].nr_thl; d++) {
                    delta = pe->dts[z].thl[d].e - pe->dts[z].thl[d].s;
                    sum += (int) delta;

                    for (int v = 0; v < 2; v++)
                        fprintf(stderr, "  ");

                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[THL],
                            delta);
                }
                if (sum) {
                    fprintf(stderr, "[%s called %d times, elapsed: %d ns]\n",
                            LB_FUNC_NAME[THL], pe->dts[z].nr_thl, sum);
                    sum = 0;
                }

                for (int d = 0; d < pe->dts[z].nr_dt; d++) {
                    //delta = pe->dts[z].dt[d].e - pe->dts[z].dt[d].s;
                    delta = pe->dts[z].dt[d].stc_e - pe->dts[z].dt[d].crl_s; // XXX for now, these represents overhead of dt
                    sum += (int) delta;

                    for (int v = 0; v < 2; v++)
                        fprintf(stderr, "  ");

                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[DETACH_TASK],
                            delta);

                    /* deactivate_task call site */
                    delta = pe->dts[z].dt[d].crl_e - pe->dts[z].dt[d].crl_s;
if (delta > maxl){
    maxl = delta;
    maxI = i;
    mdelta = pe->dts[z].dt[d].stc_e - pe->dts[z].dt[d].crl_s;
}
                    for (int v = 0; v < 3; v++)
                        fprintf(stderr, "  ");

                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[CRLUT],
                            delta);

                    /* set_task_cpu call site */
                    delta = pe->dts[z].dt[d].stc_e - pe->dts[z].dt[d].crl_e;
if (delta > maxl2){
    maxl2 = delta;
    maxI2 = i;
    mdelta2 = pe->dts[z].dt[d].stc_e - pe->dts[z].dt[d].crl_s;
}
                    for (int v = 0; v < 3; v++)
                        fprintf(stderr, "  ");

                    fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[STC],
                            delta);
                }
                if (sum) {
                    fprintf(stderr, "[%s called %d times, elapsed: %d ns]\n",
                            LB_FUNC_NAME[DETACH_TASK], pe->dts[z].nr_dt, sum);
                    sum = 0;
                }
            }

            /* attach_tasks call site */
            for (int z = 0; z < pe->nr_ats; z++) {
                delta = pe->ats[z].e - pe->ats[z].s;

                for (int v = 0; v < 1; v++) /* TODO if we still using this, macro it */
                    fprintf(stderr, "  ");

                fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[ATS], delta);
            }

            /* stop_one_cpu_nowait call site */
            for (int z = 0; z < pe->nr_socn; z++) {
                delta = pe->socn[z].e - pe->socn[z].s;

                for (int v = 0; v < 1; v++) /* TODO if we still using this, macro it */
                    fprintf(stderr, "  ");

                fprintf(stderr, "%s -> %ld ns\n", LB_FUNC_NAME[SOCN], delta);
            }

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

//     report max event 
    fprintf(stderr, "\n----------------\n");
    fprintf(stderr, "the max event:\n\n");
    fprintf(stderr, "delta: %f ms, start: %ld, end: %ld\n",
            max.delta / 1000000., max.t1, max.t2);
    fprintf(stderr, "stacktrace:\n");
    print_stacktrace(stackmap_fd, max.stack_id);
    fprintf(stderr, "----------------\n");
*/

    if (stackmap_cc)
        fprintf(stderr, "Stackmap collision occured %d time%s, plz consider "
                "increase the map size!\n", stackmap_cc, stackmap_cc > 1 ? "s"
                : "");

    report_log2(hist_map);
    fprintf(stderr, "max deactivate_task: %d ns, index: %d, detach_task costs: %dns\n", maxl, maxI, mdelta);
    fprintf(stderr, "max set_task_cpu: %d ns, index: %d, detach_task costs: %dns\n", maxl2, maxI2, mdelta2);
}

/*
 * Check if the desired amount of event has reached, `target_ev` would be
 * LB_EVENT_SZ if not specified at cmdline.
 */
static bool should_stop(int target_ev)
{
/*
     once all of the CPUs reached the amount, stop profiling
    for (int c = 0; c < nproc; c++) {
         paired with __sync_fetch_and_add() in the BPF prog 
        if (__atomic_load_n(&skel->bss->map.cpu[c].idx, __ATOMIC_ACQUIRE) ==
            target_ev) {
            continue;
        } else {
            return false;
        }
    }
    return true;*/
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}

/* TODO for a more robust event (not a truncated one which typically occurs at the start of the profiling), */
/* we need to employ percpu state tracking, if the state is not the expected state, we fallback to the first state */
/* FIXME we waste 8 bytes for stack_id field, which only used in KP_LB event */
/* consider using variable-length event */
/* XXX consider add a check in BPF progs for checking buffer overrun. I.e. */
/* check retval of bpf_perf_event_output() */
static int ringbuf_cb(void *ctx, void *data, size_t size)
{
    const struct lb_event *e = (struct lb_event*) data;
    struct prof_entry *pe;
    enum lb_ev_type *last_state = &res.cpu_last_state[e->cpu];
    int idx;
    int *idx_p;

    if (unlikely(res.nr_cpu_ev[e->cpu] >= NR_ENTRY_PERCPU)) {
        fprintf(stderr, "WARN: Buffer for CPU%d has no space left\n", e->cpu);
        return 0; /* if we return negavite val, other CPUs event  */
    }

    /* FIXME this abstraction looks nasty, put nr_cpu_ev into struct `cpu` and rename to nr_ev */
    pe = res.cpu[e->cpu] + res.nr_cpu_ev[e->cpu];

    switch (e->type) {
    case STC_E:
        /* detach_task has 2 possible caller, this filters out the not interested one */
        if (unlikely(*last_state != CRLUT_E))
            break;
        idx_p = &pe->dts[pe->nr_dts].nr_dt;
        /* no way this can greater than MAX_NR_MIGRATION */
        assert(*idx_p <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].dt[*idx_p].stc_e = e->ts;
        *last_state = STC_E;
        (*idx_p)++; // XXX STC_E now acts as index updater for detach_task
        break;
    case CRLUT_S: /* this acts as start event of detach_task */
        /* XXX
         * should this condition be true, it can be:
         * 1. buffer overrun
         * 2. we are at early stage of the profiling, i.e. some BPF progs
         *      haven't successfully attached yet.
         * 3. unexpected call site calls triggered this event, for detach_task,
         *      callers except detach_tasks is stop_one_cpu_nowait.
         */
        if (unlikely(*last_state != DETACH_TASKS_S && *last_state != STC_E))
            break;
        idx = pe->dts[pe->nr_dts].nr_dt;
        /* no way this can greater than MAX_NR_MIGRATION */
        assert(idx <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].dt[idx].crl_s = e->ts;
        *last_state = CRLUT_S;
        break;
    case CRLUT_E:
        if (unlikely(*last_state != CRLUT_S))
            break;
        idx = pe->dts[pe->nr_dts].nr_dt; // no need to update as it's DETACH_TASK_E's job
        /* no way this can greater than MAX_NR_MIGRATION */
        assert(idx <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].dt[idx].crl_e = e->ts;
        *last_state = CRLUT_E;
        break;
    case CMT_S:
        idx = pe->dts[pe->nr_dts].nr_cmt;
        assert(idx <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].cmt[idx].s = e->ts;
        break;
    case CMT_E:
        idx_p = &pe->dts[pe->nr_dts].nr_cmt;
        assert(*idx_p <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].cmt[*idx_p].e = e->ts;
        (*idx_p)++;
        break;
    case THL_S:
        idx = pe->dts[pe->nr_dts].nr_thl;
        assert(idx <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].thl[idx].s = e->ts;
        break;
    case THL_E:
        idx_p = &pe->dts[pe->nr_dts].nr_thl;
        assert(*idx_p <= MAX_NR_MIGRATION);
        pe->dts[pe->nr_dts].thl[*idx_p].e = e->ts;
        (*idx_p)++;
        break;
    case DETACH_TASKS_S: /* load_balance may call this multiple times */
        if (unlikely(*last_state != KP_LB))
            break;

        idx = pe->nr_dts;
        if (unlikely(idx >= MAX_NR_DTS_ITER)) {
            fprintf(stderr, "MAX_NR_DTS_ITER hit, consider increase the size!\n");
            exit(-1);
        }
        pe->dts[idx].s = e->ts;
        *last_state = DETACH_TASKS_S;
        break;
    case DETACH_TASKS_E:
        if (unlikely(*last_state != STC_E && *last_state != DETACH_TASKS_S))
            break;
        idx_p = &pe->nr_dts;
        assert(*idx_p <= MAX_NR_DTS_ITER);
        pe->dts[*idx_p].e = e->ts;
        (*idx_p)++;
        *last_state = DETACH_TASKS_E;
        break;
    case ATS_S: /* load_balance may call me multiple times */
        idx = pe->nr_ats;
        if (unlikely(idx >= MAX_NR_ATS_ITER)) {
            fprintf(stderr, "MAX_NR_ATS_ITER hit, consider increase the size!\n");
            exit(-1);
        }
        pe->ats[idx].s = e->ts;
//XXX        *last_state = DETACH_TASKS_S;
        break;
    case ATS_E:
        idx_p = &pe->nr_ats;
        assert(*idx_p <= MAX_NR_ATS_ITER);
        pe->ats[*idx_p].e = e->ts;
        (*idx_p)++;
//XXX        *last_state = DETACH_TASKS_E;
        break;
    case SOCN_S: /* load_balance may call me multiple times */
        idx = pe->nr_socn;
        if (unlikely(idx >= MAX_NR_SOCN_ITER)) {
            fprintf(stderr, "MAX_NR_SOCN_ITER hit, consider increase the size!\n");
            exit(-1);
        }
        pe->socn[idx].s = e->ts;
//XXX        *last_state = DETACH_TASKS_S;
        break;
    case SOCN_E:
        idx_p = &pe->nr_socn;
        assert(*idx_p <= MAX_NR_SOCN_ITER);
        pe->socn[*idx_p].e = e->ts;
        (*idx_p)++;
//XXX        *last_state = DETACH_TASKS_E;
        break;
    case FBG_S: /* load_balance may call me multiple times */
        idx = pe->nr_fbg;
        if (unlikely(idx >= MAX_NR_FBG_ITER)) {
            fprintf(stderr, "MAX_NR_FBG_ITER hit, consider increase the size!\n");
            exit(-1);
        }
        pe->fbg[idx].s = e->ts;
//XXX        *last_state = DETACH_TASKS_S;
        break;
    case FBG_E:
        idx_p = &pe->nr_fbg;
        assert(*idx_p <= MAX_NR_FBG_ITER);
        pe->fbg[*idx_p].e = e->ts;
        (*idx_p)++;
//XXX        *last_state = DETACH_TASKS_E;
        break;
    case FBQ_S: /* load_balance may call me multiple times */
        idx = pe->nr_fbq;
        if (unlikely(idx >= MAX_NR_FBQ_ITER)) {
            fprintf(stderr, "MAX_NR_FBQ_ITER hit, consider increase the size!\n");
            exit(-1);
        }
        pe->fbq[idx].s = e->ts;
//XXX        *last_state = DETACH_TASKS_S;
        break;
    case FBQ_E:
        idx_p = &pe->nr_fbq;
        assert(*idx_p <= MAX_NR_FBQ_ITER);
        pe->fbq[*idx_p].e = e->ts;
        (*idx_p)++;
//XXX        *last_state = DETACH_TASKS_E;
        break;
    case KP_LB:
        /* XXX move this accordingly if we change the event prolog */
        /* happens at the early stage, where some BPF progs haven't started yet */
        /* or it's because of buffer overrun, i.e. LB_E not called for the prev ev, */
        /* so that nr_cpu_ev didn't update */
        if (unlikely(*last_state != LB_E)) {
            fprintf(stderr, "Possible buffer overrun occurred at CPU%d entry no.%d\n",
                    e->cpu, res.nr_cpu_ev[e->cpu]);
            for (int i = 0; i <= pe->nr_dts; i++) {
                pe->dts[i].nr_dt = 0;
                pe->dts[i].nr_cmt = 0;
                pe->dts[i].nr_thl = 0;
            }
            pe->nr_dts = 0;
            pe->nr_ats = 0;
            pe->nr_socn = 0;
            pe->nr_fbq = 0;
            pe->nr_fbg = 0;
        }

        pe->lb_s = e->ts;
        pe->stack_id = e->stack_id;
        *last_state = KP_LB;
        break;
    case LB_E:
        if (unlikely(*last_state != KP_LB && *last_state != DETACH_TASKS_E)) {
            fprintf(stderr, "Possible buffer overrun at CPU%d entry no.%d\n",
                    e->cpu, res.nr_cpu_ev[e->cpu]);
            for (int i = 0; i <= pe->nr_dts; i++) {
                pe->dts[i].nr_dt = 0;
                pe->dts[i].nr_cmt = 0;
                pe->dts[i].nr_thl = 0;
            }
            pe->nr_dts = 0;
            pe->nr_ats = 0;
            pe->nr_socn = 0;
            pe->nr_fbq = 0;
            pe->nr_fbg = 0;
            break;
        }

        pe->lb_e = e->ts;
        *last_state = LB_E;

        res.nr_cpu_ev[e->cpu]++;

        break;
    default:
        fprintf(stderr, "Seen unknown event from the ringbuf\n");
        exit(-1);
    }

    return 0;
}

int main(int ac, char *av[])
{
    int err;
    struct ring_buffer *rb;
    unsigned int target_ev = LB_EVENT_SZ;

 //   libbpf_set_print(libbpf_print_fn);

    if (ac == 2)
        target_ev = atoi(av[1]);

    bump_memlock_rlimit();

    if (load_kallsyms()) {
        fprintf(stderr, "Failed to process /proc/kallsyms\n");
        return -1;
    }

    nproc = get_nprocs_conf();

    res.cpu = calloc(nproc, sizeof(struct prof_entry *));
    if (!res.cpu) {
        fprintf(stderr, "Failed to calloc for res.cpu\n");
        return -1;
    }
    for (int i = 0; i < nproc; i++) {
        res.cpu[i] = calloc(NR_ENTRY_PERCPU, sizeof(struct prof_entry));
        if (!res.cpu[i]) {
            fprintf(stderr, "Failed to calloc for res.cpu[%d]\n", i);
            /* TODO let the OS to bother with the dynamic mem */
            return -1;
        }
    }
    res.cpu_last_state = calloc(nproc, sizeof(enum lb_ev_type));
    res.nr_cpu_ev = calloc(nproc, sizeof(int));
    if (!res.cpu_last_state || !res.nr_cpu_ev) {
        /* TODO free mem */
        fprintf(stderr, "Failed to calloc for res\n");
        return -1;
    }

    /* init the state so that we save a if-condition in the hotpath */
    for (int i = 0; i < nproc; i++)
        res.cpu_last_state[i] = LB_E;

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    /* FIXME unless otherwise necessary, this can shrink into time_in_lb_bpf__open_and_load */
    err = time_in_lb_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), ringbuf_cb, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
//int tt;
    while (!exiting /*&& !should_stop(target_ev)*/) {
        ring_buffer__poll(rb, 100 /* timeout, ms */);
/*
        if (-1 < (tt=__atomic_load_n(&skel->data->tf, __ATOMIC_ACQUIRE)))
            fprintf(stderr, "PASSED: %d\n", tt);
        else
            fprintf(stderr, "havent PASSED: %d\n", tt);
  */
    }

    /* to timely check BPF_STATS */
 //   system("../tools/bpftool prog list > bpftool_list_res");

    report_result();

cleanup:
    time_in_lb_bpf__destroy(skel);
    ring_buffer__free(rb);
    for (int i = 0; i < nproc; i++)
        free(res.cpu[i]);
    free(res.cpu);
    free(res.cpu_last_state);
    free(res.nr_cpu_ev);

    return err < 0 ? -err : 0;
}

