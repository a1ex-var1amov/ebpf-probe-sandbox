#!/bin/bash
set -e

# Directory for the eBPF files
WORKDIR="/app"

echo "Compiling eBPF program..."
clang -O2 -target bpf -c $WORKDIR/bpf_program.bpf.c -o $WORKDIR/bpf_program.bpf.o

echo "Compiling user-space loader..."
gcc -o $WORKDIR/main $WORKDIR/main.c -lbpf

echo "Running user-space loader to attach eBPF program..."
$WORKDIR/main
