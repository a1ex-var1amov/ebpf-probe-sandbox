#!/bin/bash
set -e

echo "Compiling eBPF program..."
clang -O2 -target bpf -c bpf_program.bpf.c -o bpf_program.bpf.o

echo "Compiling user-space loader..."
gcc -o main main.c -lbpf

echo "Loading eBPF program..."
./main
