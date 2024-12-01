# Stage 1: Build the eBPF program
FROM amazonlinux:2 AS builder

# Install dependencies for building eBPF programs
RUN yum groupinstall -y "Development Tools" && \
    yum install -y clang llvm kernel-headers kernel-devel \
                   elfutils-libelf-devel zlib-devel libbpf-devel && \
    yum clean all

# Set up the working directory
WORKDIR /app

# Copy source files
COPY bpf_program.bpf.c main.c /app/

# Compile the eBPF program
RUN clang -target bpf -O2 -I/usr/include/ -c /app/bpf_program.bpf.c -o /app/bpf_program.bpf.o && \
    gcc -o /app/main /app/main.c -lbpf

# Final stage: Lightweight runtime image
FROM alpine:latest

# Install tools to handle packaging
RUN apk add --no-cache zip

# Set up output directory
WORKDIR /output

# Copy compiled binaries from the builder stage
COPY --from=builder /app/bpf_program.bpf.o /output/
COPY --from=builder /app/main /output/

# Package the binaries into a zip file
RUN zip ebpf-app.zip bpf_program.bpf.o main

# Automatically copy files to a mounted volume and stop the container
CMD ["sh", "-c", "cp /output/* /host-output/ && echo 'Files copied to host-output!'"]