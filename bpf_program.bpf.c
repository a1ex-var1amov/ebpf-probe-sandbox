#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Define the expected tracepoint context structure
struct trace_event_raw_sys_enter {
    long unsigned int common_type;
    long unsigned int common_flags;
    long unsigned int common_preempt_count;
    int common_pid;
    long unsigned int id;
    long unsigned int args[6];
};

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    const char *filename;
    const char *const *argv;

    // Access arguments directly from the context
    bpf_probe_read_user(&filename, sizeof(filename), (void *)ctx->args[0]);
    bpf_probe_read_user(&argv, sizeof(argv), (void *)ctx->args[1]);

    // Read the filename
    char buf[16];
    bpf_probe_read_user(buf, sizeof(buf), filename);

    // Check if the command is "cat"
    if (__builtin_memcmp(buf, "cat", 3) != 0) {
        return 0;
    }

    // Log the command name
    bpf_printk("Hello! Detected 'cat' command: %s\n", buf);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";