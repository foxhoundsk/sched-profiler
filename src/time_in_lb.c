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
    fprintf(stderr, "SIGINT received, doing post-processing...");
}
/*
static int handle_event(void *ctx, void *data, size_t size)
{
    lb_event_t *e = data;

    if (unlikely(res[c].nr_deq_ev == EVENT_SZ || res[c].nr_enq_ev == EVENT_SZ))
        return -EXFULL;

    if (e->smp_cpu & LB_END_EVENT_BIT) {
        res[c].deq[res[c].nr_deq_ev] = *e;
        res[c].deq[res[c].nr_deq_ev].smp_cpu &= ~LB_END_EVENT_BIT;
        res[c].nr_deq_ev++;
    } else
        res[c].enq[res[c].nr_enq_ev++] = *e;

    return 0;
}
*/
int nproc;
struct lb_percpu_arr *map;
struct result *res;

static void report_result(void)
{
    int orphan_event = 0, zero = 0, err;

    err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.map), &zero, map);
    if (err) {
        fprintf(stderr, "Error lookup BPF map\n");
        return;
    }
// IF RESULT IS WEIRD, TRY FLUSH CACHE WITH SYSTEM('ECHO ... > /SYS/CACHE....')
    for (int c = 0; c < nproc; c++) {
        for (int i = 0; i < map[c].idx; i++) {
            if (map[c].e[i].time_ns & LB_END_EVENT_BIT) {
                map[c].e[i].time_ns &= ~LB_END_EVENT_BIT;
                res[c].deq[res[c].nr_deq_ev] = map[c].e[i];
                res[c].nr_deq_ev++;
            } else {
                res[c].enq[res[c].nr_enq_ev] = map[c].e[i];
                res[c].nr_enq_ev++;
            }
        }

        for (int i = 0; i < res[c].nr_enq_ev; i++) {
            for (int x = 0; x < res[c].nr_deq_ev; x++) {
                if (res[c].deq[x].time_ns & LB_END_EVENT_BIT) /* processed event */
                    continue;

                long delta = res[c].deq[x].time_ns - res[c].enq[i].time_ns;

                /*
                 * nearing the start or the end of profiling, or, the ringbuf can't
                 * keep up with the event rate, hence losing the corresponding
                 * event. Give up this event pair.
                 */
                if (unlikely(delta < 0)) {
                    res[c].deq[x].time_ns |= LB_END_EVENT_BIT; /* mark as processed */
                    orphan_event++;
                    break;
                }

                res[c].deq[x].time_ns |= LB_END_EVENT_BIT;

                printf("%ld\n", delta);
                break;
            }
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
            res[0].nr_enq_ev + res[0].nr_deq_ev, // TODO make this percpu
            res[0].nr_enq_ev,
            res[0].nr_deq_ev,
            orphan_event);
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
    map = malloc(sizeof(*map) * nproc);
    res = malloc(sizeof(*res) * nproc);
    if (!map || !res) {
        fprintf(stderr, "Failed to malloc\n");
        return -1;
    }
    memset(res, 0, sizeof(*res) * nproc);
    memset(map, 0, sizeof(*map) * nproc);

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
    report_result();
    fprintf(stderr, "\ndone post processing, press enter to exit...");
    getchar();

cleanup:
    time_in_lb_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
