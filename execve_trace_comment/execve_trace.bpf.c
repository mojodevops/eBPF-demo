#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// 定义事件结构（用户态和内核态共享）
struct event {
	__u32 pid;
	char filename[256];  // 存储执行的文件路径
};

// 定义 perf_event 缓冲区
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1024);
} events SEC(".maps");

// 获取 execve 的第一个参数（filename）
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
	struct event e = {};
	const char *filename = (const char *)ctx->args[0];  // args[0] 是被执行的文件路径

    // 获取当前进程 PID
	e.pid = bpf_get_current_pid_tgid() >> 32;

    // 安全拷贝用户态的文件路径字符串
	bpf_probe_read_user_str(e.filename, sizeof(e.filename), filename);

    // 提交数据到 perf 缓冲区
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

char _license[] SEC("license") = "GPL";
