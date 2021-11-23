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
        __uint(max_entries, 2 * 1024 * 1024  2MB ); 
} rb SEC(".maps");
*/

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, sizeof(lb_percpu_arr_t));
} map SEC(".maps");

#ifdef DEBUG
/*
 * @dropped
 *
 * monitor whether the backlog is big enough. (BPF ringbuf uses a lightweight.
 * spinlock internally, can we keep up with this in sched code path?)
 *
 * btw, should we align up to 128 bytes instead of 64 bytes to prevent
 * false-sharing?
 */
unsigned long dropped __attribute__((aligned(128))) = 0;
#endif

/*
 * hook location:
 * https://elixir.bootlin.com/linux/v5.14/source/kernel/sched/fair.c#L9973
 */
SEC("sched/cfs_trigger_load_balance_start")
int BPF_PROG(lb_start)
{
    lb_percpu_arr_t *ev;
    __u32 zero = 0;

    ev = bpf_map_lookup_elem(&map, &zero);
    //e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!ev) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
    if (ev->idx >= EVENT_SZ || ev->e > (ev + 1)){
//bpf_printk("%px %px-%px\n", ev->e, ev, ev + 1);
        return 0;}
//bpf_printk("idx: %u\n", ev->idx);
    ev->e[ev->idx].time_ns = bpf_ktime_get_ns();
    ev->idx++;
    //e->smp_cpu = bpf_get_smp_processor_id();
    /*
     * leave the flag zero here to leave the determination of the wakeup to
     * libbpf.
     *
     * we can use flag BPF_RB_FORCE_WAKEUP or BPF_RB_NO_WAKEUP to do more
     * fine-grained control over the wakeup (of user app. polling with
     * epoll(2) (which is what flag zero actually uses).
     */
    //bpf_ringbuf_submit(e, 0);

    return 0;
}

/*
 * hook location:
 * https://elixir.bootlin.com/linux/v5.14/source/kernel/sched/fair.c#L9734
 */
SEC("sched/cfs_trigger_load_balance_end")
int BPF_PROG(lb_end)
{
    lb_percpu_arr_t *ev;
    __u32 zero = 0;
    ev = bpf_map_lookup_elem(&map, &zero);
    //e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!ev) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
    if (ev->idx >= EVENT_SZ || ev->e < (ev + 1))
        return 0;
    ev->e[ev->idx].time_ns = bpf_ktime_get_ns() | LB_END_EVENT_BIT;
    ev->idx++;
 //   e->smp_cpu = bpf_get_smp_processor_id() | LB_END_EVENT_BIT;

//    bpf_ringbuf_submit(e, 0);

    return 0;
}

