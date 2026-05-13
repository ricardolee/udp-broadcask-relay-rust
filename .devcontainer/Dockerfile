FROM mcr.microsoft.com/devcontainers/rust:latest

# Install network tools for testing
RUN apt-get update && apt-get install -y \
    iproute2 \
    netcat-openbsd \
    python3 \
    procps \
    && rm -rf /var/lib/apt/lists/*
