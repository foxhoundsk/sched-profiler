#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> /* system() */
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
static int nproc;
static this_cpu_idx_t *this_cpu_idx;

/*
 * this dummy stops the BPF progs, i.e. they would return early instead of
 * doing normal stuff.
 */
static this_cpu_idx_t *end_prof_dummy;

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
    int zero = 0, err;

    fprintf(stderr, "\nSIGINT received, doing post-processing...\n");

    /* save current index before populating with the end_dummy */
    err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.this_cpu_idx), &zero,
                            this_cpu_idx);
    if (err) {
        fprintf(stderr, "Failed to lookup BPF map\n");
        exit(-1);
    }
    err = bpf_map_update_elem(bpf_map__fd(skel->maps.this_cpu_idx), &zero,
                              end_prof_dummy, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update BPF map\n");
        exit(-1);
    }

    exiting = true;
}

static void report_result(void)
{
    int orphan_event = 0, err, tt_enq = 0, tt_deq = 0;
    lb_event_t *map;
    struct result *res;

    res = malloc(sizeof(*res) * nproc);
    map = malloc(sizeof(*map) * nproc);
    if (!map || !res) {
        fprintf(stderr, "Failed to malloc\n");
        return;
    }
    memset(res, 0, sizeof(*res) * nproc);

    for (int key = 0; key < EVENT_SZ; key++) {
        /* BPF_MAP_BATCH_LOOKUP_ELEM can reduce syscalls */
        err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.map), &key, map);
        if (err) {
            fprintf(stderr, "Failed to lookup BPF map\n");
            return;
        }
        for (int c = 0; c < nproc; c++) {
            /* exceeds max entry of this cpu */
            if (this_cpu_idx[c].nr_event <= key)
                continue;

            if (map[c].time_ns & LB_END_EVENT_BIT) {
                res[c].deq[res[c].nr_deq_ev++].time_ns = map[c].time_ns &
                                                         ~LB_END_EVENT_BIT;
            } else {
                res[c].enq[res[c].nr_enq_ev++].time_ns = map[c].time_ns;
            }
        }
    }

    for (int c = 0; c < nproc; c++) {
        tt_enq += res[c].nr_enq_ev;
        tt_deq += res[c].nr_deq_ev;
        fprintf(stderr, "CPU: %d has %4d LB_START event(s), %4d LB_END "
                "event(s), total of %4d\n",
                c, res[c].nr_enq_ev, res[c].nr_deq_ev,
                res[c].nr_enq_ev + res[c].nr_deq_ev);
        for (int i = 0; i < res[c].nr_enq_ev; i++) {
            /* TODO
             * by using percpu_array, we can start from previous event, instead
             * of the first event, since it's not possible that the event pair
             * can interleave with each other.
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
                 */
                if (unlikely(delta < 0)) {
                    /* mark as processed (deprecated) */
                    res[c].deq[x].time_ns |= LB_END_EVENT_BIT;
                    orphan_event++;
                    continue;
                }

                res[c].deq[x].time_ns |= LB_END_EVENT_BIT;

                printf("%ld\n", delta);
                break;
            }
        }
    }

    /*
     * for minimizing measurement overhead, some metrics are
     * disabled for normal compilation. I.e., mertics that
     * enclosed by the DEBUG flag.
     */
#ifdef DEBUG
    fprintf(stderr, "dropped %ld event(s)\n",
            __atomic_load_n(&skel->bss->dropped, __ATOMIC_RELAXED));
#endif
    fprintf(stderr, "captured %d event(s)\nLB_START event: %d, "
            "LB_END event: %d\norphan event: %d\n",
            tt_enq + tt_deq,
            tt_enq,
            tt_deq,
            orphan_event);
    free(map);
}

/*
 * Check if the desired amount of event has reached, `target_ev` would be
 * EVENT_SZ if not specified at cmdline.
 */
static bool should_stop(int target_ev)
{
    int err, zero = 0;

    err = bpf_map_lookup_elem(bpf_map__fd(skel->maps.this_cpu_idx), &zero, this_cpu_idx);
    if (err) {
        fprintf(stderr, "Failed to lookup BPF map\n");
        return true;
    }

    /* once all of the CPUs reached the amount, stop profiling */
    for (int c = 0; c < nproc; c++) {
        if (this_cpu_idx[c].nr_event == target_ev) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

int main(int ac, char *av[])
{
    int err, target_ev = EVENT_SZ;

    if (ac == 2)
        target_ev = atoi(av[1]);

    nproc = get_nprocs_conf();

    end_prof_dummy = malloc(sizeof(*end_prof_dummy) * nproc);
    if (!end_prof_dummy) {
        fprintf(stderr, "Failed to malloc\n");
        return -1;
    }
    this_cpu_idx = malloc(sizeof(*this_cpu_idx) * nproc);
    if (!this_cpu_idx) {
        fprintf(stderr, "Failed to malloc\n");
        free(end_prof_dummy);
        return -1;
    }

    for (int i = 0; i < nproc; i++)
        end_prof_dummy[i].nr_event = EVENT_SZ;

    bump_memlock_rlimit();

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

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

    while (!exiting && !should_stop(target_ev)) {
        sleep(5);
    }

    /* to check BPF_STATS accurately */
    system("../tools/bpftool prog list > bpftool_list_res");

    /*
     * wait a moment before retrieving the result, as the BPF progs may still
     * updating the entries we're interested in.
     */
    sleep(1);

    report_result();
    fprintf(stderr, "\ndone post processing, press enter to exit...");
    getchar();

cleanup:
    time_in_lb_bpf__destroy(skel);
    free(end_prof_dummy);
    free(this_cpu_idx);

    return err < 0 ? -err : 0;
}
