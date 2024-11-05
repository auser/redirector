# Builder stage
FROM rust:1.75-slim-bullseye AS builder

# Install build dependencies including OpenSSL
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        build-essential \
        protobuf-compiler \
        musl-tools \
        libssl-dev \
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user to build the application
RUN useradd -m -U app

# Set up build directory
WORKDIR /build

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY .git ./.git

# Cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy source code
COPY src src/
COPY build.rs ./build.rs

# Build the application with optimizations
RUN cargo build --release

# Runtime stage
FROM debian:bullseye-slim AS runtime

# Install runtime dependencies
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        tzdata \
        openssl \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running the application
RUN useradd -m -U app

# Copy the binary from builder
COPY --from=builder /build/target/release/redirector /usr/local/bin/
RUN chmod +x /usr/local/bin/redirector

# Set up configuration
WORKDIR /app
COPY config /app/config/

# Use non-root user
USER app

# Environment variables
ENV RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD curl -f http://localhost:3000/health || exit 1

# Expose port
EXPOSE 3000

# Run the application
CMD ["redirector"]