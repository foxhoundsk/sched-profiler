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

/* CAUTION: PERCPU_ARRAY has size limitation of 32KB */
/* https://elixir.bootlin.com/linux/v5.15/source/include/linux/percpu.h#L23 */
/* https://elixir.bootlin.com/linux/v5.15/source/mm/percpu.c#L1756 */
struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, EVENT_SZ);
        __type(key, __u32);
        __type(value, sizeof(lb_event_t));
} map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, sizeof(this_cpu_idx_t));
} this_cpu_idx SEC(".maps");
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
    lb_event_t *ev, *p_ev;
    this_cpu_idx_t *idx;
    __u32 zero = 0;

    idx = bpf_map_lookup_elem(&this_cpu_idx, &zero);
    if (!idx) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
    if (idx->nr_event == EVENT_SZ)
        return 0;

    ev = bpf_map_lookup_elem(&map, &idx->nr_event);
    if (!ev) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
/*
if (idx->nr_event != 0) { turns out we can see what lb_end saved to the map
__u32 tmp;
tmp = idx->nr_event-1;
p_ev = bpf_map_lookup_elem(&map, &tmp);
if (!p_ev)
    return 0;
bpf_printk("cur_idx: %u, prev time_ns: %ld\n", idx->nr_event, p_ev->time_ns);
}*/
//bpf_printk("START\n");
    ev->time_ns = bpf_ktime_get_ns();
//bpf_printk("%ld\n", ev->time_ns);
    idx->nr_event++;
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
    lb_event_t *ev;
    this_cpu_idx_t *idx;
    __u32 zero = 0;
    idx = bpf_map_lookup_elem(&this_cpu_idx, &zero);
    if (!idx) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
    if (idx->nr_event == EVENT_SZ)
        return 0;

    ev = bpf_map_lookup_elem(&map, &idx->nr_event);
    if (!ev) {
#ifdef DEBUG
        __sync_fetch_and_add(&dropped, 1);
#endif
        return 0;
    }
//bpf_printk("previous time_ns: %ld, target idx: %u\n", ev->time_ns, idx->nr_event);
    ev->time_ns = bpf_ktime_get_ns() | LB_END_EVENT_BIT;
    idx->nr_event++;
//bpf_printk("END %lu idx: %u\n", ev->time_ns, idx->nr_event);

    return 0;
}

