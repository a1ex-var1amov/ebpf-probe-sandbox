#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define TASK_COMM_LEN 16
#define MAX_ARGS_SIZE 256

struct syscall_event {
    char comm[TASK_COMM_LEN];
    char args[MAX_ARGS_SIZE];
    int pid;
    int uid;
    int syscall;
};

static int handle_event(void *ctx, void *data, size_t len) {
    struct syscall_event *event = data;
    printf("Syscall detected: comm=%s, args=%s, pid=%d, uid=%d, syscall=%d\n",
           event->comm, event->args, event->pid, event->uid, event->syscall);
    return 0;
}

static int attach_tracepoint(struct bpf_program *prog, const char *category, const char *name) {
    if (!prog) {
        printf("Program not found for tracepoint %s:%s, skipping.\n", category, name);
        return 1;
    }

    struct bpf_link *link = bpf_program__attach_tracepoint(prog, category, name);
    if (!link) {
        perror("Failed to attach to tracepoint");
        return 1;
    }
    printf("Attached to tracepoint: %s:%s\n", category, name);
    return 0;
}

int main() {
    struct bpf_object *obj;
    struct bpf_program *prog_execve, *prog_ptrace, *prog_unshare;
    struct ring_buffer *rb;

    obj = bpf_object__open_file("alex_probe.bpf.o", NULL);
    if (!obj) {
        perror("Failed to open eBPF object file");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("Failed to load eBPF object");
        bpf_object__close(obj);
        return 1;
    }

    printf("eBPF programs available:\n");
    bpf_object__for_each_program(prog_execve, obj) {
        printf(" - %s\n", bpf_program__name(prog_execve));
    }

    prog_execve = bpf_object__find_program_by_name(obj, "trace_execve");
    attach_tracepoint(prog_execve, "syscalls", "sys_enter_execve");

    prog_ptrace = bpf_object__find_program_by_name(obj, "trace_ptrace");
    attach_tracepoint(prog_ptrace, "syscalls", "sys_enter_ptrace");

    prog_unshare = bpf_object__find_program_by_name(obj, "trace_unshare");
    attach_tracepoint(prog_unshare, "syscalls", "sys_enter_unshare");

    int map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "syscall_events"));
    if (map_fd < 0) {
        perror("Failed to find ring buffer map");
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        perror("Failed to create ring buffer");
        bpf_object__close(obj);
        return 1;
    }

    printf("Monitoring syscalls...\n");

    while (1) {
        ring_buffer__poll(rb, -1);
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}