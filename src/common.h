#ifndef __COMMON_H
#define __COMMON_H

#define DEQ_EVENT_BIT 0x80000000
#define LB_END_EVENT_BIT 0x8000000000000000
#define LB_EVENT_SZ 8192
#define RQ_EVENT_SZ 1024
#define HIST_MAP_BUCKET_SZ 16
#define PERF_MAX_STACK_DEPTH 127 /* from /usr/include/linux/perf_event.h */
#define NPROC 16 /* power of 2 */

/* hardcoded 64-byte cacheline alignment */
#define __cacheline_aligned __attribute__ ((aligned(64)))

struct rq_event {
    int pid;
    long time_ns;
    unsigned long nr_migrations; /* se.nr_migrations */
    unsigned long ctxt_switches; /* nvcsw + nivcsw */
};
typedef struct rq_event rq_event_t;

/*
 * kernel do 8-byte alignment on at least PERCPU_ARRAY map, hence corresponding
 * userspace alignment is required.
 */
struct this_cpu_idx {
    unsigned int nr_event;
} __cacheline_aligned;
typedef struct this_cpu_idx this_cpu_idx_t;

struct lb_iter_cnt {
    int redo;
    int mb;
};

struct percpu_event {
    unsigned int idx;

    /*
     * TODO consider reduce size of this field, as it only uses odd idx.
     * naive way is add another index for the field.  Same is true for lb_iter.
     */
    unsigned long stack_id[LB_EVENT_SZ];
    long time_ns[LB_EVENT_SZ];
    struct lb_iter_cnt lb_iter[LB_EVENT_SZ];
} __cacheline_aligned;

/* S: start, E: end */
enum lb_ev_type {
    THL_S, /* task_h_load */
    THL_E,
    CMT_S, /* can_migrate_task */
    CMT_E,
    ATS_S, /* attach_tasks */
    ATS_E,
    SOCN_S, /* stop_one_cpu_nowait */
    SOCN_E,
    FBQ_S, /* find_busiest_queue */
    FBQ_E,
    FBG_S, /* find_busiest_group */
    FBG_E,
    CRLUT_S, /* cfs_rq_last_update_time */
    CRLUT_E,
    STC_E, /* set_task_cpu (use CRLUT_E as the start event) */
    DETACH_TASK_S,
    DETACH_TASK_E,
    DETACH_TASKS_S,
    DETACH_TASKS_E,
    DEQ_TASK_CLS_S, /* dequeue_task - this is sched class spcific */
    DEQ_TASK_CLS_E,
    SCD_E, /* sched_core_dequeue - use CRLUT_S as the start event */
    URC_S, /* update_rq_clock */
    URC_E,
    SIDPD_S, /* sched_info_dequeue and psi_dequeue */
    SIDPD_E,
    KP_LB, /* kprobe load_balance */
    LB_E, /* load_balance end */
    NR_EVENT,
};

struct lb_event {
    enum lb_ev_type type;
    long ts;
    long stack_id;
    int cpu;
};

static unsigned int to_log2(unsigned int v)
{
	unsigned int r;
	unsigned int shift;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);
	return r;
}

#endif /* __COMMON_H */
