# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM rust:1-bookworm AS builder

# (args from Docker BuildKit)
ARG TARGETPLATFORM
ARG BUILDPLATFORM

RUN case "$TARGETPLATFORM" in \
        'linux/amd64') echo 'export RUST_TARGET=x86_64-unknown-linux-gnu' > /rust_env.sh ;; \
        'linux/arm64') echo 'export RUST_TARGET=aarch64-unknown-linux-gnu' > /rust_env.sh ;; \
        *) echo "Unsupported platform: ${TARGETPLATFORM}" && exit 1 ;; \
    esac && \
    . /rust_env.sh && \
    rustup target add "$RUST_TARGET"

RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates \
    curl \
    git && \
    if [ "$TARGETPLATFORM" = 'linux/arm64' ] && [ "$BUILDPLATFORM" != 'linux/arm64' ]; then \
        apt-get install --no-install-recommends -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross && \
        printf '%s\n' \
            'export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc' \
            'export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc' \
            'export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++' \
            >> /rust_env.sh; \
    else \
        apt-get install --no-install-recommends -y build-essential; \
    fi

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY misc/github-action.sh ./github-action.sh

RUN cargo fetch --locked

RUN . /rust_env.sh && \
    cargo build --locked --release --target="$RUST_TARGET" \
        --bin datadog-static-analyzer \
        --bin datadog-static-analyzer-git-hook \
        --bin datadog-static-analyzer-server && \
    mkdir -p /target && \
    cp "target/$RUST_TARGET/release/datadog-static-analyzer" /target/ && \
    cp "target/$RUST_TARGET/release/datadog-static-analyzer-git-hook" /target/ && \
    cp "target/$RUST_TARGET/release/datadog-static-analyzer-server" /target/

FROM node:24-bookworm-slim

RUN npm install -g @datadog/datadog-ci@^4 --no-audit --no-fund --progress=false --no-update-notifier --loglevel=error && \
    datadog-ci --version

COPY --from=builder /target/datadog-static-analyzer /usr/bin/datadog-static-analyzer
COPY --from=builder /target/datadog-static-analyzer-server /usr/bin/datadog-static-analyzer-server
COPY --from=builder /target/datadog-static-analyzer-git-hook /usr/bin/datadog-static-analyzer-git-hook
COPY --from=builder /app/github-action.sh /usr/bin/github-action.sh

ENTRYPOINT ["/usr/bin/datadog-static-analyzer"]
CMD ["--help"]
