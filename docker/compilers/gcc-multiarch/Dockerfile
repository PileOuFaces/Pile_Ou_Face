FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    # x86 / x86-64
    gcc g++ \
    gcc-i686-linux-gnu g++-i686-linux-gnu \
    # ARM / AArch64
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf \
    # Windows (MinGW)
    gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
    gcc-mingw-w64-i686 g++-mingw-w64-i686 \
    # MIPS
    gcc-mips-linux-gnu \
    gcc-mipsel-linux-gnu g++-mipsel-linux-gnu \
    gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 \
    # PowerPC
    gcc-powerpc-linux-gnu g++-powerpc-linux-gnu \
    gcc-powerpc64-linux-gnu g++-powerpc64-linux-gnu \
    gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu \
    # SPARC64
    gcc-sparc64-linux-gnu g++-sparc64-linux-gnu \
    # RISC-V 64
    gcc-riscv64-linux-gnu g++-riscv64-linux-gnu \
    # IBM SystemZ / s390x
    gcc-s390x-linux-gnu g++-s390x-linux-gnu \
    # Motorola M68K
    gcc-m68k-linux-gnu \
    # SuperH SH4
    gcc-sh4-linux-gnu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pof
COPY docker/compilers/gcc-multiarch/compile.py /opt/pof/compile.py
COPY docker/compilers/gcc-multiarch/compilers.json /opt/pof/compilers.json
