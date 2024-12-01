#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj = NULL;

    // Load the eBPF program object file
    obj = bpf_object__open_file("bpf_program.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1; // Exit with error
    }

    // Load the eBPF program into the kernel
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1; // Exit with error
    }

    printf("eBPF program loaded. Use 'dmesg' to view messages from the kernel ring buffer.\n");

    // Sleep indefinitely; the eBPF program runs independently in the kernel
    while (1) {
        sleep(10);
    }

    bpf_object__close(obj); // Close the eBPF object
    return 0;
}
