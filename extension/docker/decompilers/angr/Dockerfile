FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/pof-venv/bin:${PATH}" \
    DECOMPILERS_CONFIG=/opt/pof/decompilers.json

# Dépendances système
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        ca-certificates \
        curl \
        file \
        git \
        libffi-dev \
        libssl-dev \
        python3 \
        python3-dev \
        python3-pip \
        python3-venv \
    && rm -rf /var/lib/apt/lists/*

# ── Couche pip lourde séparée (maximise le cache) ──────────────────────────
# angr compile unicorn/pyvex/claripy depuis les sources — très lent.
# En isolant cette couche, elle est mise en cache tant que requirements.txt
# ne change pas, même si le code backends/ change.
COPY docker/decompilers/angr/requirements.txt /tmp/requirements-container.txt
RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r /tmp/requirements-container.txt

# ── Code applicatif (couche fine, invalidée souvent) ──────────────────────
WORKDIR /app
COPY backends /app/backends
# Config de décompilation embarquée dans l'image — pointée par DECOMPILERS_CONFIG
RUN mkdir -p /opt/pof
COPY docker/decompilers/angr/decompilers.json /opt/pof/decompilers.json
COPY docker/decompilers/angr/decompile.py /opt/pof/decompile.py
COPY docker/decompilers/angr/rop_build.py /opt/pof/rop_build.py
COPY docker/decompilers/angr/test_rop_build.py /opt/pof/test_rop_build.py
# Compile the test binary from source (avoids committing pre-built ELFs to git)
COPY docker/decompilers/angr/testdata/vuln.c /tmp/vuln.c
RUN mkdir -p /opt/pof/testdata \
    && gcc -m64 -fno-stack-protector -no-pie -o /opt/pof/testdata/vuln_x64.elf /tmp/vuln.c \
    && rm /tmp/vuln.c

# Utilisateur non-root
RUN useradd -m -u 10001 pof
USER pof

ENTRYPOINT []
CMD ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--list", "--provider", "local"]
