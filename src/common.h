#ifndef __COMMON_H
#define __COMMON_H

#define DEQ_EVENT_BIT 0x80000000
#define LB_END_EVENT_BIT 0x8000000000000000
#define EVENT_SZ 8 // the rq.c is now redefined

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

struct lb_percpu_arr {
    unsigned int idx;
    lb_event_t e[EVENT_SZ];
};
typedef struct lb_percpu_arr lb_percpu_arr_t;

#endif /* __COMMON_H */
