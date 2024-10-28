# Development stage
FROM rust:1.75-slim-bullseye AS development

# Install development dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    git \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set up development directory
WORKDIR /app


# Create a non-root user for development with proper cargo permissions
RUN useradd -m -s /bin/bash developer && \
echo "developer ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
mkdir -p /usr/local/cargo/registry && \
mkdir -p /app/target && \
chown -R developer:developer /app /usr/local/cargo

# Set cargo home
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup

COPY ./.devcontainer/zshrc /home/developer/.zshrc

# Switch to non-root user
USER developer

# Keep container running
CMD ["sleep", "infinity"]