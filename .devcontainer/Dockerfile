# Development stage
FROM rust:1.75-slim-bullseye AS development

# Install development dependencies
RUN apt-get -y update -yq \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        wget \
        ssh \
        sudo \
        jq \
        build-essential \
        protobuf-compiler \
        musl-dev \
        musl-tools \
        musl \
        apt-transport-https \
        ca-certificates \
        gnupg-agent \
        gnupg \
        software-properties-common \
        postgresql-client \
        npm \
        nodejs \
        zsh \
        python3-pip \
        pkg-config \
    # Clean up
    && apt-get autoremove -y \
    && apt-get clean -y \
    && rm -r /var/cache/* /var/lib/apt/lists/*

# Set up development directory
WORKDIR /app


# Create a non-root user for development with proper cargo permissions
RUN useradd -m -s /bin/zsh developer && \
echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
mkdir -p /usr/local/cargo/registry && \
mkdir -p /app/target && \
chown -R developer:developer /app /usr/local/cargo

# Set cargo home
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup

COPY ./.devcontainer/ext/zshrc /home/developer/.zshrc

# Switch to non-root user
USER developer

# Keep container running
CMD ["sleep", "infinity"]