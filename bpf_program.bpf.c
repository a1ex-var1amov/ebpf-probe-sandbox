#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// eBPF program attached to the tracepoint for `execve` syscall
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    // Extract the command and its arguments
    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];

    // Read the command name
    char command[16];
    bpf_core_read_user_str(&command, sizeof(command), filename);

    // Check if the command name matches "cat"
    if (bpf_strncmp(command, "cat", 3) != 0) {
        return 0; // Exit if the command is not "cat"
    }

    // Prepare a buffer to hold arguments
    char arg_buf[128] = {0};

    // Concatenate the first 5 arguments into a single string
    #pragma unroll
    for (int i = 0; i < 5; i++) { // Limit to 5 arguments
        const char *arg; // Pointer to the current argument
        bpf_core_read_user(&arg, sizeof(arg), &argv[i]); // Read the argument pointer
        if (!arg) {
            break; // Exit loop if no more arguments
        }
        // Append the argument to the buffer
        bpf_core_read_user_str(&arg_buf + bpf_strlen(arg_buf), sizeof(arg_buf) - bpf_strlen(arg_buf), arg);
        bpf_strncat(arg_buf, " ", sizeof(arg_buf)); // Add space between arguments
    }

    // Write a message to the kernel ring buffer (visible in dmesg)
    bpf_printk("Hello! Detected 'cat' command: %s, args: %s\n", command, arg_buf);

    return 0; // Exit the eBPF program
}

// Required license declaration for eBPF programs
char LICENSE[] SEC("license") = "BSD";

