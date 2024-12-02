#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS_SIZE 256

struct syscall_event {
    char comm[TASK_COMM_LEN];
    char args[MAX_ARGS_SIZE];
    int pid;
    int uid;
    int syscall;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} syscall_events SEC(".maps");

static __always_inline void record_event(struct trace_event_raw_sys_enter *ctx, int syscall_id) {
    struct syscall_event *event;

    event = bpf_ringbuf_reserve(&syscall_events, sizeof(struct syscall_event), 0);
    if (!event)
        return;

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->syscall = syscall_id;

    // Capture arguments only for execve
    if (syscall_id == 59) {
        bpf_probe_read_user_str(event->args, sizeof(event->args), (void *)ctx->args[0]);
    } else {
        event->args[0] = '\0';
    }

    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    record_event(ctx, 59); // Syscall ID for execve
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx) {
    record_event(ctx, 101); // Syscall ID for ptrace
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx) {
    record_event(ctx, 272); // Syscall ID for unshare
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
