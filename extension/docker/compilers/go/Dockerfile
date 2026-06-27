FROM --platform=linux/amd64 golang:1.22-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pof
COPY docker/compilers/go/compile.py /opt/pof/compile.py
COPY docker/compilers/go/compilers.json /opt/pof/compilers.json
