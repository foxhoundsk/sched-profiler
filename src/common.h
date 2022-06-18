#ifndef __COMMON_H
#define __COMMON_H

#define DEQ_EVENT_BIT 0x80000000
#define LB_END_EVENT_BIT 0x8000000000000000
#define LB_EVENT_SZ 8192
#define RQ_EVENT_SZ 1024
#define HIST_MAP_BUCKET_SZ 16
#define PERF_MAX_STACK_DEPTH 127 /* from /usr/include/linux/perf_event.h */

/* hardcoded 64-byte cacheline alignment */
#define CACHE_LINE_SIZE 64
#define __cacheline_aligned __attribute__ ((aligned(CACHE_LINE_SIZE)))

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

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
    RRD_S, /* run_rebalance_domains */
    RRD_E,
    NIB_S, /* nohz_idle_balance */
    NIB_E,
    N_IB_S, /* _nohz_idle_balance */
    N_IB_E,
    RD_S, /* rebalance_domains */
    RD_E,
    LB_S, /* load_balance */
    LB_E,
    DT_S, /* detach_tasks */
    DT_E,
    AT_S, /* attach_tasks */
    AT_E,
    ST_S, /* scheduler_tick */
    ST_E,
    TTF_S, /* task_tick_fair */
    TTF_E,
    SCHED_S, /* schedule */
    SCHED_E,
    S_CHED_S, /* __schedule */
    S_CHED_E,
    PNT_S, /* pick_next_task */
    PNT_E,
    TLB_S, /* trigger_load_balance (paired with RRD_E) */

    NR_EVENT,
};

#define TASK_COMM_LEN 16
struct hrtick_map {
    long delta;
    char comm[TASK_COMM_LEN];
};
typedef struct hrtick_map hrtick_map_t;
struct cputime_map {
    char comm[TASK_COMM_LEN];
    pid_t pid;
    long sum;
};
typedef struct cputime_map bpf_map_t;

struct cputime {
    long ts;
    long sum;
};
typedef struct cputime cputime_t;

struct sched_lat_map {
    char comm[TASK_COMM_LEN];
    pid_t pid;
    unsigned long sum;
    long cnt;
};
typedef struct sched_lat_map sched_lat_map_t;
struct sched_lat {
    long cnt; // nr times scheduled
    long ts;
    unsigned long sum;
};
typedef struct sched_lat sched_lat_t;

struct lb_event {
    enum lb_ev_type type;
    long ts;
    union {
        char comm[7];
    };
    int pid;
    int cpu;
    int ccpu;
    //int prev_pid;
    //char p_comm[7];
    unsigned prev_state;
};

/*
 * identical to lb_event except for the cpu field, which perfbuf API already has one
 */
typedef struct {
    enum lb_ev_type type;
    long ts;
    int cpu;
} event_t;

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

/* TODO use codegen to simplify this ugly macro... */
#define add_rb() do { \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb2), \
                              ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb3), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb4), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb5), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb6), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb7), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb8), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb9), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb10), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb11), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb12), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb13), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb14), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb15), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
        err = ring_buffer__add(rb, bpf_map__fd(skel->maps.rb16), \
                                  ringbuf_cb, NULL); \
        if (err) goto ringbuf_fail; \
    } while (0)

#endif /* __COMMON_H */
