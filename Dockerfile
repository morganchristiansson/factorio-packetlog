FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
# UTF-8 locale: Ruby's default external encoding comes from LANG; without
# this, File.read returns US-ASCII-flagged strings and any non-ASCII byte
# (player names, memories) blows up with Encoding::CompatibilityError.
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8

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
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    node --version && npm --version


RUN npm install -g @jmfederico/pi-web --allow-scripts=node-pty

# ── npm global packages ─────────────────────────────────────────────────────
RUN npm install -g @earendil-works/pi-coding-agent@0.84.2 && \
    pi --version

# ── Ruby gems ──────────────────────────────────────────────
# Only bundler here (the bootstrap tool itself); ALL project deps come from
# the Gemfile — run `bundle install` inside the container after checkout.
# pcaprub needs libpcap-dev + build tools (installed above) to compile its
# native extension.
RUN gem install bundler && \
    ruby --version

RUN mkdir -p /workspace
WORKDIR /workspace
USER ubuntu
