#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>

#include "common.h"
#include "time_in_lb.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define EVENT_SZ 65536 * 2

static struct {
    lb_event_t enq[EVENT_SZ]; /* 4MB */
    lb_event_t deq[EVENT_SZ];
    int nr_enq_ev;
    int nr_deq_ev;
} res = {};

static volatile bool exiting = false;
static struct time_in_lb_bpf *skel;

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
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t size)
{
    lb_event_t *e = data;

    if (unlikely(res.nr_deq_ev == EVENT_SZ || res.nr_enq_ev == EVENT_SZ))
        return -EXFULL;

    if (e->smp_cpu & LB_END_EVENT_BIT) {
        res.deq[res.nr_deq_ev] = *e;
        /*
         * move this op into the post processing if we can't keep up with the
         * event rate.
         */
        res.deq[res.nr_deq_ev].smp_cpu &= ~LB_END_EVENT_BIT;
        res.nr_deq_ev++;
    } else
        res.enq[res.nr_enq_ev++] = *e;

    return 0;
}

static void report_result(void)
{
    int orphan_event = 0;

    for (int i = 0; i < res.nr_enq_ev; i++) {
        for (int x = 0; x < res.nr_deq_ev; x++) {
            if (res.deq[x].smp_cpu & LB_END_EVENT_BIT || /* processed event */
                res.deq[x].smp_cpu != res.enq[i].smp_cpu)
                continue;

            long delta = res.deq[x].time_ns - res.enq[i].time_ns;

            /*
             * nearing the start or the end of profiling, or, the ringbuf can't
             * keep up with the event rate, hence losing the corresponding
             * event. Give up this event pair.
             */
            if (unlikely(delta < 0)) {
                res.deq[x].smp_cpu |= LB_END_EVENT_BIT; /* mark as processed */
                orphan_event++;
                break;
            }

            res.deq[x].smp_cpu |= LB_END_EVENT_BIT;

            printf("%ld\n", delta);
            break;
        }
    }
    /*
     * don't messing result we're interested in, hence stderr.
     *
     * for minimizing measurement overhead, some metrics are
     * disabled for normal compilation.
     */
#ifdef DEBUG
    fprintf(stderr, "dropped %ld event(s)\n",
            __atomic_load_n(&skel->bss->dropped, __ATOMIC_RELAXED));
#endif
    fprintf(stderr, "captured %d event(s)\nenqueue event: %d, "
            "picked-up event: %d\norphan event: %d\n",
            res.nr_enq_ev + res.nr_deq_ev,
            res.nr_enq_ev,
            res.nr_deq_ev,
            orphan_event);
}

int main(int ac, char *av[])
{
    struct ring_buffer *rb;
    int err;

    bump_memlock_rlimit();

    skel = time_in_lb_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    while (!exiting) {
        /* if not fast enough, use ring_buffer__consume() for busy reaping. */
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            fprintf(stderr, "\nSIGINT received...\n\n");
            err = 0;
            break;
        } else if (err == -EXFULL) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            goto cleanup;
        }
    }
    report_result();
    fprintf(stderr, "\ndone post processing, press enter to exit...");
    getchar();

cleanup:
    ring_buffer__free(rb);
    time_in_lb_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
