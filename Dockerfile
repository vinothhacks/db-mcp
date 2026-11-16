# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for DB-MCP Server (`db-mcp-server`)
# Default runtime command:
#   db-mcp-server serve --transport http --bind 0.0.0.0:8080 --config /etc/db-mcp/db-mcp.toml

# Cargo.lock needs rustc >= 1.89 (uuid 1.29.0); keep in sync with workspace rust-version.
FROM rust:1.89-slim-bookworm AS builder

WORKDIR /workspace

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY config ./config

RUN cargo build --release --locked -p db-mcp-server

FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system dbmcp \
    && useradd --system --gid dbmcp --create-home --home-dir /var/lib/db-mcp dbmcp \
    && mkdir -p /etc/db-mcp /var/lib/db-mcp/research/traces /var/lib/db-mcp/research/fixtures

WORKDIR /var/lib/db-mcp

COPY --from=builder /workspace/target/release/db-mcp-server /usr/local/bin/db-mcp-server
COPY --from=builder /workspace/config/db-mcp.example.toml /etc/db-mcp/db-mcp.toml
COPY --from=builder /workspace/config/db-mcp.starter.toml /etc/db-mcp/db-mcp.starter.toml

RUN chown -R dbmcp:dbmcp /etc/db-mcp /var/lib/db-mcp

USER dbmcp

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["db-mcp-server", "serve", "--transport", "http", "--bind", "0.0.0.0:8080", "--config", "/etc/db-mcp/db-mcp.toml"]
