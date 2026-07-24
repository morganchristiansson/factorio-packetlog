FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    make \
    g++ \
    ruby \
    ruby-dev \
    libpcap-dev \
    tcpdump \
    tshark \
    xxd \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    node --version && npm --version


RUN npm install -g @jmfederico/pi-web --allow-scripts=node-pty

# ── npm global packages ─────────────────────────────────────────────────────
RUN npm install -g @earendil-works/pi-coding-agent@0.82.0 && \
    pi --version

# ── Ruby gems for packet capture ─────────────────────────────────────────────
RUN gem install pcaprub packetfu && \
    ruby --version

RUN mkdir -p /workspace
WORKDIR /workspace
USER ubuntu
