FROM ubuntu:22.04

# RetDec ne fournit des binaires pré-compilés que pour linux/amd64 (x86_64).
# Cette image est donc buildée uniquement en amd64.
# Sur un hôte ARM64 (Apple Silicon, etc.), Docker/OrbStack exécute l'image
# via émulation QEMU — transparent pour l'utilisateur.
# La CI ne doit PAS tenter de builder pour linux/arm64.

ARG RETDEC_VERSION="v5.0"
ARG RETDEC_URL="https://github.com/avast/retdec/releases/download/${RETDEC_VERSION}/RetDec-${RETDEC_VERSION}-Linux-Release.tar.xz"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    RETDEC_INSTALL_DIR=/opt/retdec \
    DECOMPILERS_CONFIG=/opt/pof/decompilers.json

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        file \
        python3 \
        python-is-python3 \
        python3-pip \
        python3-venv \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN echo "==> Téléchargement du binaire RetDec pré-compilé (linux/amd64)…" \
    && mkdir -p /opt/retdec-download \
    && curl -L "${RETDEC_URL}" -o /opt/retdec-download/retdec.tar.xz \
    && mkdir -p /opt/retdec \
    && tar -xJf /opt/retdec-download/retdec.tar.xz -C /opt/retdec \
    && rm -rf /opt/retdec-download \
    && echo "✅ RetDec installé : $(ls /opt/retdec/bin/)"

WORKDIR /app
COPY extension/backends /app/backends
COPY docker/decompilers/retdec/requirements.txt /app/requirements-container.txt
# Config de décompilation embarquée dans l'image — pointée par DECOMPILERS_CONFIG
RUN mkdir -p /opt/pof
COPY docker/decompilers/retdec/decompilers.json /opt/pof/decompilers.json

RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r /app/requirements-container.txt

ENV PATH="/opt/pof-venv/bin:/opt/retdec/bin:${PATH}"

RUN useradd -m -u 10001 pof
USER pof

ENTRYPOINT []
CMD ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--list", "--provider", "local"]
