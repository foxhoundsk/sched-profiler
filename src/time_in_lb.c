#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysinfo.h> /* nproc */
#include <bpf/bpf.h>

#include "common.h"
#include "time_in_lb.skel.h"

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

struct result {
    lb_event_t enq[EVENT_SZ / 2];
    lb_event_t deq[EVENT_SZ / 2];
    int nr_enq_ev;
    int nr_deq_ev;
};

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
    fprintf(stderr, "SIGINT received, doing post-processing...\n");
}

static int nproc;

static void report_result(void)
{
    int orphan_event = 0, zero = 0, err;
    this_cpu_idx_t *this_cpu_idx;
    lb_event_t *map;
    struct result *res;

    res = malloc(sizeof(*res) * nproc);
    this_cpu_idx = malloc(sizeof(*this_cpu_idx) * nproc);
    map = malloc(sizeof(*map) * EVENT_SZ);
    if (!this_cpu_idx || !map || !res) {
        fprintf(stderr, "Failed to malloc\n");
        return;
    }
    memset(res, 0, sizeof(*res) * nproc);
    err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.this_cpu_idx), &zero, this_cpu_idx);
    if (err) {
        fprintf(stderr, "Failed to lookup BPF map\n");
        return;
    }

    for (int c = 0; c < nproc; c++) {
        int idx = this_cpu_idx[c].nr_event;
//fprintf(stderr, "cpu: %d idx: %d\n", c, idx);
        err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.map), &c, map);
        if (err) {
            fprintf(stderr, "Failed to lookup BPF map\n");
            return;
        }
        for (int i = 0; i < idx; i++) {
fprintf(stderr, "processing ns: %ld\n", map[i].time_ns);
            if (map[i].time_ns & LB_END_EVENT_BIT) {
                res[c].deq[res[c].nr_deq_ev++].time_ns = map[i].time_ns &
                                                         ~LB_END_EVENT_BIT;
//fprintf(stderr, "WWWW\n");
            } else {
                res[c].enq[res[c].nr_enq_ev++] = map[i];
            }
        }
//fprintf(stderr, "this cpu nr_enq: %d\n", res[c].nr_enq_ev);
/*
fprintf(stderr, "nr_deq_ev: %d %ld\n", res[c].nr_deq_ev, res[c].deq[0].time_ns);
fprintf(stderr, "nr_enq_ev: %d %ld\n", res[c].nr_enq_ev, res[c].enq[0].time_ns);*/
        for (int i = 0; i < res[c].nr_enq_ev; i++) {
            /* TODO
             * by using percpu_array, we can start from previous event, instead
             * of the first event, since it's not possible that the event pair
             * can interleave with each other (i.e. the SMP stuff).
             */
            for (int x = 0; x < res[c].nr_deq_ev; x++) {
                if (res[c].deq[x].time_ns & LB_END_EVENT_BIT)
                /*
                 * already processed, or nearing end of the profiling, i.e. no
                 * corresponding lb_end event found.
                 */
                    continue;

                long delta = res[c].deq[x].time_ns - res[c].enq[i].time_ns;
            /*
             * nearing the start of profiling, no matching event pair found.
             * Give up this event.
             */
                if (unlikely(delta < 0)) {
                    /* mark as processed */
                    res[c].deq[x].time_ns |= LB_END_EVENT_BIT;
                    orphan_event++;
                    break;
                }

                res[c].deq[x].time_ns |= LB_END_EVENT_BIT;

                printf("%ld\n", delta);
                break;
            }
        }
    }

// IF RESULT IS WEIRD, TRY FLUSH CACHE WITH SYSTEM('ECHO ... > /SYS/CACHE....'), this is bacause of the PERCPU_ARRAY

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
            res[0].nr_enq_ev + res[0].nr_deq_ev, // TODO make this percpu
            res[0].nr_enq_ev,
            res[0].nr_deq_ev,
            orphan_event);
    free(this_cpu_idx);
    free(map);
}

int main(int ac, char *av[])
{
    int err, map_fd, zero = 0;

    bump_memlock_rlimit();

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    nproc = get_nprocs_conf();

    err = time_in_lb_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }
/*
    map_fd = bpf_map__fd(skel->maps.map);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to obtain map fd\n");
        return -1;
    }

    err = bpf_map_update_elem(map_fd, &zero, map, BPF_NOEXIST);
    if (err) {
        fprintf(stderr, "Failed to update BPF map\n");
        return -1;
    }
*/

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    while (!exiting) {
        sleep(1);
    }
sleep(20);
    report_result();
    fprintf(stderr, "\ndone post processing, press enter to exit...");
    getchar();

cleanup:
    time_in_lb_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
