# Base development dependencies
FROM rust:1.75-slim-bullseye AS base

# Install common build dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        build-essential \
        libssl-dev \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Development stage
FROM base AS development

# Install additional development dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ssh \
        sudo \
        jq \
        protobuf-compiler \
        zsh \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-root user for development
RUN useradd -m -s /usr/bin/zsh developer && \
    echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /usr/local/cargo/registry && \
    mkdir -p /app/target && \
    chown -R developer:developer /app /usr/local/cargo

ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH="/usr/local/cargo/bin:$PATH"

USER developer
RUN cargo install cargo-watch cargo-edit cargo-expand cargo-audit


CMD ["sleep", "infinity"]

