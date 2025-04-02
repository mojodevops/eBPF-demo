#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct event {
    __u32 pid;
    char filename[256];
    char argv[5][64];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char **argv;
    int i;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), (void *)ctx->args[0]);

    argv = (const char **)(ctx->args[1]);
    #pragma unroll
    for (i = 0; i < 5; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp) break;
        bpf_probe_read_user_str(e->argv[i], sizeof(e->argv[i]), argp);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
