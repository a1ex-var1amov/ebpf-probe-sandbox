```
sudo yum update -y
sudo yum install -y clang llvm kernel-devel-$(uname -r) kernel-headers-$(uname -r) \
libbpf libbpf-devel elfutils-libelf-devel gcc gcc-c++ make bpftool

echo 1 | sudo tee /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/enable
echo 1 | sudo tee /sys/kernel/debug/tracing/events/syscalls/sys_enter_ptrace/enable
echo 1 | sudo tee /sys/kernel/debug/tracing/events/syscalls/sys_enter_unshare/enable


bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -g -O2 -target bpf -I. -c alex_probe.bpf.c -o alex_probe.bpf.o
gcc -o ebpf_loader ebpf_loader.c -lbpf
```