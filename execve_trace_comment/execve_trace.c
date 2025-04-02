#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "execve_trace.skel.h"

// 事件结构体必须与 BPF 程序一致
struct event {
    __u32 pid;
    char filename[256];
};

static volatile bool exiting = false;

// 信号处理函数
static void sig_handler(int sig) {
    exiting = true;
}

// perf 事件回调
static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct event *e = data;
    time_t now;
    struct tm *tm_info;
    char time_str[20];

    time(&now);
    tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("[%s] PID: %-8d Command: %s\n", time_str, e->pid, e->filename);  // 显示 filename
}

// 错误回调
static void handle_lost_events(void *ctx, int cpu, __u64 cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", cnt, cpu);
}

int main(int argc, char **argv) {
    struct execve_trace_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err, map_fd;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = execve_trace_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = execve_trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %d\n", err);
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.events);
    struct perf_buffer_opts pb_opts = {.sz = sizeof(struct perf_buffer_opts),};
    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, NULL,&pb_opts);
    if (!pb) {
        err = -errno;
        fprintf(stderr, "Failed to create perf buffer: %d\n", err);
        goto cleanup;
    }

    printf("Monitoring execve() syscalls. Press Ctrl+C to stop.\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    perf_buffer__free(pb);
    execve_trace_bpf__destroy(skel);
    return err != 0;
}
