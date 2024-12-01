#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

int main() {
    struct bpf_object *obj = bpf_object__open_file("/output/bpf_program.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    printf("eBPF program loaded successfully. Check dmesg for logs.\n");
    while (1) {
        sleep(10);
    }

    bpf_object__close(obj);
    return 0;
}
