# Use an Amazon Linux 2 image or a similar lightweight base with necessary tools
FROM amazonlinux:2

# Install dependencies
RUN yum groupinstall -y "Development Tools" && \
    amazon-linux-extras enable BPF && \
    yum install -y clang llvm kernel-headers kernel-devel \
                   elfutils-libelf-devel zlib-devel libbpf-devel && \
    yum clean all

# Set up the working directory
WORKDIR /app

# Copy source code and entrypoint script
COPY bpf_program.bpf.c .
COPY main.c .
COPY entrypoint.sh .

# Set the entrypoint
ENTRYPOINT ["/bin/bash", "/app/entrypoint.sh"]
