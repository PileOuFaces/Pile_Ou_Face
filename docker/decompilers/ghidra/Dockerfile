FROM ubuntu:24.04

# Ghidra version à télécharger (headless, via GitHub releases)
ARG GHIDRA_VERSION="12.0.4"
ARG GHIDRA_DATE="20260303"
ARG GHIDRA_SHA256="c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
ARG GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip"

# TARGETARCH est injecté automatiquement par docker buildx (amd64 ou arm64)
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    GHIDRA_USER_PROJECTS=/tmp/ghidra_projects \
    PATH="/opt/pof-venv/bin:/opt/ghidra/support:${PATH}"

# Dépendances système : JDK 21 requis par Ghidra 11+, Python 3, unzip
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        openjdk-21-jdk-headless \
        python3 \
        python3-pip \
        python3-venv \
        unzip \
        wget \
    && rm -rf /var/lib/apt/lists/*

# JAVA_HOME : détection dynamique de l'arch réelle
RUN DPKG_ARCH=$(dpkg --print-architecture) \
    && JH="/usr/lib/jvm/java-21-openjdk-${DPKG_ARCH}" \
    && if [ ! -d "$JH" ]; then \
         JH=$(find /usr/lib/jvm -maxdepth 1 -name 'java-21-openjdk*' -type d | head -1); \
       fi \
    && echo "JAVA_HOME=$JH" >> /etc/environment \
    && echo "export JAVA_HOME=$JH" >> /etc/profile.d/java_home.sh \
    && ln -sfn "$JH" /usr/lib/jvm/java-21-openjdk-current
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-current

# Téléchargement et installation de Ghidra headless
RUN apt-get update \
    && apt-get install -y --no-install-recommends g++ make bison flex \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /opt/ghidra-download \
    && wget -q "${GHIDRA_URL}" -O /opt/ghidra-download/ghidra.zip \
    && unzip -q /opt/ghidra-download/ghidra.zip -d /opt/ghidra-tmp \
    && mv /opt/ghidra-tmp/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm -rf /opt/ghidra-download /opt/ghidra-tmp

# Compiler le binaire natif decompile pour arm64 (absent du zip Ghidra officiel).
# TARGETARCH est injecté par docker buildx ; fallback sur uname -m pour builds locaux.
RUN if [ "${TARGETARCH}" = "arm64" ] || { [ -z "${TARGETARCH}" ] && [ "$(uname -m)" = "aarch64" ]; }; then \
        cd /opt/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp \
        && make ghidra_opt ARCH_TYPE="" \
        && mkdir -p /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64 \
        && cp ghidra_opt /opt/ghidra/Ghidra/Features/Decompiler/os/linux_arm_64/decompile \
        && make clean; \
    fi

WORKDIR /app
COPY extension/backends /app/backends
# requirements propre au container ghidra (lief + capstone)
COPY docker/decompilers/ghidra/requirements.txt /app/requirements-container.txt
# Config de décompilation embarquée dans l'image — pointée par DECOMPILERS_CONFIG
# L'user n'a pas à la modifier : elle contient les commandes locales de l'outil.
RUN mkdir -p /opt/pof
COPY docker/decompilers/ghidra/decompilers.json /opt/pof/decompilers.json
COPY docker/decompilers/ghidra/decompile.py /opt/pof/decompile.py
COPY docker/decompilers/ghidra/script.py /opt/pof/script.py

# Venv Python + dépendances minimales du container
RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r /app/requirements-container.txt

# Utilisateur non-root + permissions runtime
RUN useradd -m -u 10001 pof \
    && mkdir -p /tmp/ghidra_projects /tmp/pof_work \
    && chmod 1777 /tmp \
    && chown -R pof:pof /tmp/ghidra_projects /tmp/pof_work /home/pof \
    && chown -R root:pof /opt/ghidra \
    && chmod -R g+rX /opt/ghidra \
    && chmod g+rwX /opt/ghidra

USER pof

ENV GHIDRA_INSTALL_DIR=/opt/ghidra \
    HOME=/home/pof \
    GHIDRA_USER_PROJECTS=/tmp/ghidra_projects \
    JDK_JAVA_OPTIONS="-Djava.awt.headless=true -Djava.net.preferIPv4Stack=true -Xmx2g" \
    DECOMPILERS_CONFIG=/opt/pof/decompilers.json

ENTRYPOINT []
CMD ["/opt/pof-venv/bin/python", "-m", "backends.static.decompile", "--list", "--provider", "local"]
