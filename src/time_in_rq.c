#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>

#include "common.h"
#include "time_in_rq.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)
#define EVENT_SZ 65536 * 2

static struct {
    rq_event_t enq[EVENT_SZ]; /* 4MB */
    rq_event_t deq[EVENT_SZ];
    int nr_enq_ev;
    int nr_deq_ev;
} res = {};

static volatile bool exiting = false;
static struct time_in_rq_bpf *skel;

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
    rq_event_t *e = data;

    if (unlikely(res.nr_deq_ev == EVENT_SZ || res.nr_enq_ev == EVENT_SZ))
        return -EXFULL;

    if (e->pid & DEQ_EVENT_BIT) {
        res.deq[res.nr_deq_ev] = *e;
        /*
         * move this op into post processing if we can't keep up with the event
         * rate.
         */
        res.deq[res.nr_deq_ev].pid &= ~DEQ_EVENT_BIT;
        res.nr_deq_ev++;
    } else
        res.enq[res.nr_enq_ev++] = *e;

    return 0;
}

static void report_result(void)
{
    int orphan_event = 0;
/*
printf("pid: %d, nr_migra: %lu, ctxt_switches: %lu\n", res.enq[0].pid, res.enq[0].nr_migrations, res.enq[0].ctxt_switches);
printf("pid: %d, nr_migra: %lu, ctxt_switches: %lu\n", res.deq[0].pid, res.deq[0].nr_migrations, res.deq[0].ctxt_switches);
printf("pid: %d, nr_migra: %lu, ctxt_switches: %lu\n", res.deq[1].pid, res.deq[1].nr_migrations, res.deq[1].ctxt_switches);
return;
*/
    for (int i = 0; i < res.nr_enq_ev; i++) {
        /*
         * picked-up event may not ordered, we have no choice but start from 1st
         * entry for each search.
         */
        for (int x = 0; x < res.nr_deq_ev; x++) {
            if (likely(
                (res.deq[x].pid & DEQ_EVENT_BIT) || /* processed entry */
                res.enq[i].pid           != res.deq[x].pid ||
                res.enq[i].nr_migrations != res.deq[x].nr_migrations ||
                res.enq[i].ctxt_switches != res.deq[x].ctxt_switches)) {
                /*
                 * No matching event pair found. It could be:
                 * 1. event recorded at early stage of the profiling.
                 * 2. the ringbuf can't keep up with the event rate of the
                 *    scheduler.
                 * 3. task got stolen by another CPU.
                 */
                if (unlikely(x == res.nr_deq_ev - 1)) {
                    /*
                     * For the 3rd reason listed above, we need to find the
                     * enqueue event of the migration, and update its timestamp
                     * , then we won't lost waiting time span before the
                     * migration.
                     */
                    for (int z = (i + 1) < res.nr_enq_ev ? i + 1 :
                         res.nr_enq_ev; z < res.nr_enq_ev; z++) {
                        if (res.enq[i].pid == res.enq[z].pid &&
                            res.enq[i].nr_migrations ==
                                (res.enq[z].nr_migrations - 1) &&

                            /*
                             * Prevent collision with newly created task, some
                             * distros have random generated pid, it's possible
                             * to collide with different actual task.
                             */
                            res.enq[i].ctxt_switches ==
                                res.enq[z].ctxt_switches) {
                            res.enq[z].time_ns = res.enq[i].time_ns;
                            break;
                        }
                    }
                    orphan_event++;
                }
                continue;
            }
            res.deq[x].pid |= DEQ_EVENT_BIT; // mark as processed entry
            printf("%ld\n", res.deq[x].time_ns - res.enq[i].time_ns);
            break;
        }
    }
    /*
     * don't mess up result we're interested in, hence stderr.
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

    skel = time_in_rq_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return -1;
    }

    err = time_in_rq_bpf__attach(skel);
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
        /* if not fast enough, use ring_buffer__consume() */
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
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
    time_in_rq_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
