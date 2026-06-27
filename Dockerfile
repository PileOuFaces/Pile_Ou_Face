FROM node:22-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/pof-venv/bin:${PATH}"

WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        file \
        git \
        libyara-dev \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        yara \
    && rm -rf /var/lib/apt/lists/* \
    && addgroup --system pof \
    && adduser --system --ingroup pof pof

COPY extension/package.json extension/package-lock.json ./extension/
RUN cd extension && npm ci

COPY backends/requirements.txt ./backends/requirements.txt
RUN python3 -m venv /opt/pof-venv \
    && /opt/pof-venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/pof-venv/bin/pip install --no-cache-dir -r backends/requirements.txt

COPY . .
RUN chown -R pof:pof /workspace /opt/pof-venv

USER pof

CMD ["bash"]
