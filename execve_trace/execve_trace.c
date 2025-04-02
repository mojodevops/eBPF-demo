#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "execve_trace.skel.h"

struct event {
    __u32 pid;
    char filename[256];
    char argv[5][64];
};

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;

    printf("PID: %d, CMD: %s", e->pid, e->filename);
    for (int i = 0; i < 5; i++) {
        if (e->argv[i][0] == '\0') break;
        printf(" %s", e->argv[i]);
    }
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    struct execve_trace_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = execve_trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = execve_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("✅ Monitoring execve() calls... Press Ctrl+C to exit.\n");

    while (!exiting) {
        ring_buffer__poll(rb, 100);
    }

cleanup:
    ring_buffer__free(rb);
    execve_trace_bpf__destroy(skel);
    return 0;
}
