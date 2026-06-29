FROM --platform=linux/amd64 rust:1.82-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80retries
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    # Linkers for cross-compilation targets
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    gcc-mingw-w64-x86-64 \
    gcc-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu \
    gcc-powerpc64le-linux-gnu \
    gcc-sparc64-linux-gnu \
    gcc-riscv64-linux-gnu \
    gcc-s390x-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

# Tier-2 targets with prebuilt std (MIPS dropped to tier 3 in Rust 1.73)
RUN rustup target add \
    aarch64-unknown-linux-gnu \
    armv7-unknown-linux-gnueabihf \
    x86_64-pc-windows-gnu \
    powerpc-unknown-linux-gnu \
    powerpc64-unknown-linux-gnu \
    powerpc64le-unknown-linux-gnu \
    sparc64-unknown-linux-gnu \
    riscv64gc-unknown-linux-gnu \
    s390x-unknown-linux-gnu

WORKDIR /opt/pof
COPY docker/compilers/rust/compile.py /opt/pof/compile.py
COPY docker/compilers/rust/compilers.json /opt/pof/compilers.json
