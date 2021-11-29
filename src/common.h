#ifndef __COMMON_H
#define __COMMON_H

#define DEQ_EVENT_BIT 0x80000000
#define LB_END_EVENT_BIT 0x8000000000000000
#define EVENT_SZ 8192 // the rq.c is now redefined

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
} __attribute__ ((aligned(8)));
typedef struct lb_event lb_event_t;

/*
 * kernel do 8-byte alignment on at least PERCPU_ARRAY map, hence corresponding
 * userspace alignment is required.
 */
struct this_cpu_idx {
    unsigned int nr_event;
} __attribute__ ((aligned(8)));
typedef struct this_cpu_idx this_cpu_idx_t;

struct lb_percpu_arr {
    unsigned int idx;
    lb_event_t e[EVENT_SZ];
};
typedef struct lb_percpu_arr lb_percpu_arr_t;

#endif /* __COMMON_H */
