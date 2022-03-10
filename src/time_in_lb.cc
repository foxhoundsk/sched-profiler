#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h> /* for system() */
#include <unistd.h>
#include <sys/sysinfo.h> /* for nproc TODO libbpf already has such API */
#include <bpf/bpf.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common.h"
#include "trace_helpers.h"
#include "time_in_lb.skel.h"

/*
 * As long as BPF map can keep up with the sched event rate, this ringbuf is
 * not necessary.
 */
//#include "SPSCQueue.h"

#include <time.h>

/* perfetto specific */
#include <fstream>
#include "perfetto.h"

PERFETTO_DEFINE_CATEGORIES(
    perfetto::Category("sched")
        .SetDescription("CPU Scheduler event"));

/* init static storage for the categories */
PERFETTO_TRACK_EVENT_STATIC_STORAGE();

/* perfetto specific */

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* TODO add this to cmdline option */
#define EVENT_THRES     5000

#define NR_ENTRY_PERCPU (1024 * 512)
#define EVENT_RINGBUF_SZ (1 << 16)
#define TRACE_FILENAME "sched_event.pftrace"

/* for full name of these timestamps, refer LB_FUNC_NAME */
struct prof_entry { /* profiling entry */
    long lb_s;
    long lb_e;
    long pne_s;
    long pne_e;
};

struct result {
    //struct prof_entry **cpu;
    enum lb_ev_type *cpu_last_state;
    int *nr_cpu_ev;
};

static volatile bool exiting = false;
static struct time_in_lb_bpf *skel;
static int nproc;
static struct result res;
//static rigtorp::SPSCQueue<event_t> buf(EVENT_RINGBUF_SZ);
//static int trace_fd;

/* occupies 2 cachelines so that vars after this won't involve false-sharing
 * either.
 */
static volatile bool worker_should_exit __attribute__
    ((aligned(CACHE_LINE_SIZE * 2))) = false ;

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
    fprintf(stderr, "\nSIGINT received, doing post-processing...\n");
    exiting = true;
}

/* it's fine to truncate @delta, as it should not exceed 32-bit */
static void record_log2(int *hist_map, unsigned delta)
{
    int log = to_log2(delta);

    if (log >= HIST_MAP_BUCKET_SZ)
        log = HIST_MAP_BUCKET_SZ - 1;

    hist_map[log]++;
}

static inline void report_log2(int *hist_map)
{
    fprintf(stderr, "\nTIME(ns)\t HITCOUNT\n");
    for (int i = 0; i < HIST_MAP_BUCKET_SZ; i++) {
        fprintf(stderr, "%5d -> %5d: %5d\n", 1 << i, 1 << (i + 1), hist_map[i]);
    }
}
/*
static void report_result(void)
{
    int hist_map[HIST_MAP_BUCKET_SZ] = {};

    for (int c = 0; c < nproc; c++) {
        for (int i = 0; i < res.nr_cpu_ev[c]; i++) {
            struct prof_entry *pe = res.cpu[c] + i;
            long delta = pe->lb_e - pe->lb_s;

            record_log2(hist_map, delta);
            //printf("%ld\n", delta);


        }
    }

    report_log2(hist_map);
}
*/
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
        return vfprintf(stderr, format, args);
}

static void perfbuf_cb(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    const struct lb_event *e = (struct lb_event*) data;
    enum lb_ev_type *last_state = &res.cpu_last_state[cpu];
    cpu++; /* to shift the index to appropriate perfetto track */

    switch (e->type) {
    case PNT_S:
        if (unlikely(*last_state != PNT_E))
            fprintf(stderr, "Possible buffer overrun occurred at CPU%d\n",
                    cpu);

        //buf.emplace((event_t) {.type = PNT_S, .ts = e->ts, .cpu = cpu});
        TRACE_EVENT_BEGIN("sched", "pick_next_task_fair", perfetto::Track(cpu), (uint64_t) e->ts);
        *last_state = PNT_S;

        break;
    case PNE_S:
        if (unlikely(*last_state != PNT_S)) {
            /* to prevent unintended caller, but then we're risking
             * lost of possible buffer overrun event.
             */
            break;
        }

        //buf.emplace((event_t) {.type = PNE_S, .ts = e->ts, .cpu = cpu});
        TRACE_EVENT_BEGIN("sched", "pick_next_entity", perfetto::Track(cpu), (uint64_t) e->ts);
        *last_state = PNE_S;

        break;
    case PNE_E:
        if (unlikely(*last_state != PNE_S)) {
            break;
        }

        //buf.emplace((event_t) {.type = PNE_E, .ts = e->ts, .cpu = cpu});
        TRACE_EVENT_END("sched", perfetto::Track(cpu), (uint64_t) e->ts);
        *last_state = PNE_E;

        break;
    case PNT_E:
        if (unlikely(*last_state != PNT_S && *last_state != PNE_E)) {
            fprintf(stderr, "Possible buffer overrun occurred at CPU%d\n",
                    cpu);
            break;
        }

        //buf.emplace((event_t) {.type = PNT_E, .ts = e->ts, .cpu = cpu});
        TRACE_EVENT_END("sched", perfetto::Track(cpu), (uint64_t) e->ts);
        *last_state = PNT_E;

        break;
    }
}

std::unique_ptr<perfetto::TracingSession> StartTracing() {
    // The trace config defines which types of data sources are enabled for
    // recording. In this example we just need the "track_event" data source,
    // which corresponds to the TRACE_EVENT trace points.
    perfetto::TraceConfig cfg;
    cfg.set_duration_ms((uint32_t) 1000 * 180);
    cfg.set_write_into_file(true);
    cfg.set_output_path(TRACE_FILENAME);
    cfg.set_flush_period_ms(250);

    /* TODO currently confused with this knob, the higher it is, the higher the
     * likelihood calling to TRACE_EVENT_*() would stall. The confusion is,
     * this knob should have nothing to do with the shmem, what it affects is
     * the central buffer, which we currently have 2GB for it, i.e., it should
     * have no affect on the overrun of the shmem buffer.
     *
     * It should be noted that if the stall duration is too long, Perfetto
     * would consider there is a possible deadlock, and stop the application
     * abnormaly.
     *
     * Plus, the flush period should be as longer as possible, since we want
     * minimal interference to the machine being traced.
     */
    cfg.set_file_write_period_ms(3500);

    auto buffer_cfg = cfg.add_buffers();
    buffer_cfg->set_size_kb(1024 * 1024 * 2);
    auto ds = cfg.add_data_sources();
    auto ds_cfg = ds->mutable_config();
    ds_cfg->set_name("track_event");
    // ds_cfg->kBufferExhaustedPolicy = perfetto::BufferExhaustedPolicy::kStall;

    auto tracing_session = perfetto::Tracing::NewTrace();
    tracing_session->Setup(cfg);
    tracing_session->StartBlocking();
    return tracing_session;
}

void StopTracing(std::unique_ptr<perfetto::TracingSession> tracing_session) {
  // flush track event out of the shmem
  perfetto::TrackEvent::Flush();

  // Stop tracing and read the trace data.
  tracing_session->StopBlocking();/*
  std::vector<char> trace_data(tracing_session->ReadTraceBlocking());

  // Write the result into a file.
  // Note: To save memory with longer traces, you can tell Perfetto to write
  // directly into a file by passing a file descriptor into Setup() above.
  std::ofstream output;
  output.open("sched_event.pftrace",
              std::ios::out | std::ios::binary);
  output.write(&trace_data[0], trace_data.size());
  output.close();
*/
}

std::unique_ptr<perfetto::TracingSession> init_perfetto(void)
{
    perfetto::TracingInitArgs args;

    /* must below 32MB, or it's ignored */
    args.shmem_size_hint_kb = 1024 * 32;

    args.backends = perfetto::kInProcessBackend;
 //   args.
    perfetto::Tracing::Initialize(args);

    /* init track events */
    perfetto::TrackEvent::Register();

    return StartTracing();
}

/*
static void* buf_consumer(void *d __attribute__((unused)))
{
    while (likely(!worker_should_exit)) {
        do {
keep_working:
            auto *e = buf.front();

            if (likely(e != nullptr)) {
                enum lb_ev_type *last_state = &res.cpu_last_state[e->cpu];

                switch (e->type) {
                case PNT_S:
                    TRACE_EVENT_BEGIN("sched", "pick_next_task_fair", perfetto::Track(e->cpu), (uint64_t) e->ts);
                    break;
                case PNE_S:
                    TRACE_EVENT_BEGIN("sched", "pick_next_entity", perfetto::Track(e->cpu), (uint64_t) e->ts);
                    break;
                case PNE_E:
                    TRACE_EVENT_END("sched", perfetto::Track(e->cpu), (uint64_t) e->ts);
                    break;
                case PNT_E:
                    TRACE_EVENT_END("sched", perfetto::Track(e->cpu), (uint64_t) e->ts);
                    break;
                }

                buf.pop();

                // it's likely that we have enormous events to process
                goto keep_working;
            }
        } while (likely(!buf.empty()));
        // FIXME we seldom reach here as the sched events happens very frequent.
        // Have been considering placing pthread_yield() here, but the manpage
        // says that it should only be used in sched policies other than
        // SCHED_OTHERS. Do we have better mechanism for scenario where the
        // event rate is low?

    }

    fprintf(stderr, "worker has stopped\n");
}
*/
int main(int ac, char *av[])
{
    int err;
    struct perf_buffer *pb = NULL;
    struct perf_buffer_opts pb_opts = {};
    //pthread_t worker;

    //libbpf_set_print(libbpf_print_fn);

    auto tracing_session = init_perfetto();
    if (tracing_session == nullptr) {
        fprintf(stderr, "Failed to init perfetto\n");
        return -1;
    }

    //pthread_create(&worker, NULL, buf_consumer, NULL);

    bump_memlock_rlimit();

    nproc = get_nprocs_conf();

    /* rename perfetto track for each CPU */
    for (int i = 1; i < nproc + 1; i++) {
        char cpu[] = "CPUXXX"; // 3 digits should do the trick
        snprintf(cpu, sizeof(cpu), "CPU%d", i - 1);
        auto desc = perfetto::Track(i).Serialize();
        desc.set_name(cpu);
        perfetto::TrackEvent::SetTrackDescriptor(perfetto::Track(i), desc);
    }

/*
    res.cpu = (prof_entry**) calloc(nproc, sizeof(struct prof_entry *));
    if (!res.cpu) {
        fprintf(stderr, "Failed to calloc for res.cpu\n");
        return -1;
    }
    for (int i = 0; i < nproc; i++) {
        res.cpu[i] = (prof_entry*) calloc(NR_ENTRY_PERCPU, sizeof(struct prof_entry));
        if (!res.cpu[i]) {
            fprintf(stderr, "Failed to calloc for res.cpu[%d]\n", i);
            return -1;
        }
    }
*/
    res.cpu_last_state = (lb_ev_type*) calloc(nproc, sizeof(enum lb_ev_type));
    res.nr_cpu_ev = (int*) calloc(nproc, sizeof(int));
    if (!res.cpu_last_state || !res.nr_cpu_ev) {
        /* TODO free mem */
        fprintf(stderr, "Failed to calloc for res\n");
        return -1;
    }

    /* init the state so that we save a if-condition in the hotpath */
    for (int i = 0; i < nproc; i++)
        res.cpu_last_state[i] = PNT_E;

    skel = time_in_lb_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return -1;
    }

    /* unless otherwise necessary, this can shrink into time_in_lb_bpf__open_and_load */
    err = time_in_lb_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program\n");
        return -1;
    }

    pb_opts.sample_cb = perfbuf_cb;
    pb = perf_buffer__new(bpf_map__fd(skel->maps.pb), 1024 /* 16KB per CPU */,
                          &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    err = time_in_lb_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    __atomic_store_n(&skel->bss->start_tracing, 1, __ATOMIC_RELEASE);

    while (!exiting) {
        perf_buffer__poll(pb, 100 /* timeout, ms */);
    }
/*
    worker_should_exit = true;
    pthread_join(worker, NULL);
*/
    /* to timely check BPF_STATS */
    system("../tools/bpftool prog list > bpftool_list_res");

    //report_result();
    fprintf(stderr, "BPF dropped %ld event(s)\n",
            __atomic_load_n(&skel->bss->dropped, __ATOMIC_ACQUIRE));

cleanup:
    time_in_lb_bpf__destroy(skel);
    perf_buffer__free(pb);
/*
    for (int i = 0; i < nproc; i++)
        free(res.cpu[i]);
    free(res.cpu);
*/
    free(res.cpu_last_state);
    free(res.nr_cpu_ev);

    StopTracing(std::move(tracing_session));

    //close(trace_fd);

    return err < 0 ? -err : 0;
}

