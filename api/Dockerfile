# syntax=docker/dockerfile:1.7
#
# Multi-stage, multi-arch build for ridm-api.
#
#   docker buildx build --platform linux/amd64,linux/arm64 -f api/Dockerfile -t ridm .
#
# Stage 1 builds the UI's static export (`ui/out`) once, on the build
# platform: it is the same files for every architecture. Stage 2 builds the
# release binary for the target platform with that export compiled in
# (`--features embedded-ui`; `kerberos` adds desktop sign-in), so the image
# serves the sign-in pages and both consoles on the API's own origin. Stage 3 copies the binary into a
# distroless image (no shell, no package manager, runs as non-root).

ARG RUST_VERSION=1.98.1
ARG NODE_VERSION=24.21.0

# ---------------------------------------------------------------------------
# ui
# ---------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM node:${NODE_VERSION}-bookworm-slim AS ui

WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui ./
# Same-origin build: an empty NEXT_PUBLIC_API_URL makes every page call the
# host it was loaded from, which is the API serving it.
ENV NEXT_PUBLIC_API_URL="" NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# ---------------------------------------------------------------------------
# builder
# ---------------------------------------------------------------------------
FROM rust:${RUST_VERSION}-bookworm AS builder

RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake clang libclang-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Cache dependency compilation separately from source changes. Cargo loads the
# manifest of every workspace member even when only one package is built, so
# each member needs its Cargo.toml and a stub target here — including
# `ridm-cli`, `ridm-auth` and the examples, which the image does not ship.
COPY Cargo.toml Cargo.lock ./
COPY api/Cargo.toml api/Cargo.toml
COPY crates/ridm-core/Cargo.toml crates/ridm-core/Cargo.toml
COPY crates/ridm-cli/Cargo.toml crates/ridm-cli/Cargo.toml
COPY crates/ridm-auth/Cargo.toml crates/ridm-auth/Cargo.toml
COPY examples/axum-api/Cargo.toml examples/axum-api/Cargo.toml
COPY examples/confidential-client/Cargo.toml examples/confidential-client/Cargo.toml
RUN mkdir -p api/src crates/ridm-core/src crates/ridm-cli/src crates/ridm-auth/src \
      examples/axum-api/src examples/confidential-client/src \
 && echo 'fn main() {}' > api/src/main.rs \
 && echo '' > api/src/lib.rs \
 && echo '' > crates/ridm-core/src/lib.rs \
 && echo 'fn main() {}' > crates/ridm-cli/src/main.rs \
 && echo '' > crates/ridm-auth/src/lib.rs \
 && echo 'fn main() {}' > examples/axum-api/src/main.rs \
 && echo 'fn main() {}' > examples/confidential-client/src/main.rs \
 && cargo build --release --locked -p ridm-api --features embedded-ui,kerberos \
 && rm -rf api/src crates/ridm-core/src crates/ridm-cli/src crates/ridm-auth/src \
      examples/axum-api/src examples/confidential-client/src

COPY api api
COPY crates crates
COPY examples/axum-api examples/axum-api
COPY examples/confidential-client examples/confidential-client
COPY --from=ui /src/ui/out ui/out
# Touch sources so cargo notices they changed after the dependency-only build.
RUN touch api/src/main.rs api/src/lib.rs crates/ridm-core/src/lib.rs \
 && cargo build --release --locked -p ridm-api --features embedded-ui,kerberos \
 && strip target/release/ridm-api

# ---------------------------------------------------------------------------
# runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="rIDM" \
      org.opencontainers.image.description="Multi-tenant OpenID Connect identity server" \
      org.opencontainers.image.source="https://github.com/ZerosAndOnesLLC/rIDM" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /src/target/release/ridm-api /ridm-api

ENV BIND_ADDR=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot

# The binary probes its own /healthz (distroless has no curl): the bind
# address, over TLS when TLS_CERT/TLS_KEY are set.
HEALTHCHECK --interval=15s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/ridm-api", "--healthcheck"]

ENTRYPOINT ["/ridm-api"]
