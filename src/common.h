#ifndef __COMMON_H
#define __COMMON_H

#define DEQ_EVENT_BIT 0x80000000
#define LB_END_EVENT_BIT 0x8000000000000000
#define LB_EVENT_SZ 8192
#define RQ_EVENT_SZ 1024
#define HIST_MAP_BUCKET_SZ 16
#define PERF_MAX_STACK_DEPTH 127 /* from /usr/include/linux/perf_event.h */

/* hardcoded 64-byte cacheline alignment */
#define __cacheline_aligned __attribute__ ((aligned(64)))

struct rq_event {
    int pid;
    long time_ns;
    unsigned long nr_migrations; /* se.nr_migrations */
    unsigned long ctxt_switches; /* nvcsw + nivcsw */
};
typedef struct rq_event rq_event_t;

struct lb_event {
    long time_ns;
    //int smp_cpu;
};
typedef struct lb_event lb_event_t;

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
