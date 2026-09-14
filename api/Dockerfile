# syntax=docker/dockerfile:1.7
#
# Multi-stage, multi-arch build for ridm-api.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
#
# Stage 1 builds the release binary for the target platform. Stage 2 copies it
# into a distroless image (no shell, no package manager, runs as non-root).
# The UI is embedded into the binary in Phase 11.1; until then the image serves
# the API only.

ARG RUST_VERSION=1.98.1

# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
COPY api/Cargo.toml api/Cargo.toml
COPY crates/ridm-core/Cargo.toml crates/ridm-core/Cargo.toml
RUN mkdir -p api/src crates/ridm-core/src \
 && echo 'fn main() {}' > api/src/main.rs \
 && echo '' > api/src/lib.rs \
 && echo '' > crates/ridm-core/src/lib.rs \
 && cargo build --release --locked -p ridm-api \
 && rm -rf api/src crates/ridm-core/src

COPY api api
COPY crates crates
# Touch sources so cargo notices they changed after the dependency-only build.
RUN touch api/src/main.rs api/src/lib.rs crates/ridm-core/src/lib.rs \
 && cargo build --release --locked -p ridm-api \
 && strip target/release/ridm-api

# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="rIDM" \
      org.opencontainers.image.description="Multi-tenant OpenID Connect identity server" \
      org.opencontainers.image.source="https://github.com/mack42/rIDM" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /src/target/release/ridm-api /ridm-api

ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/ridm-api"]
