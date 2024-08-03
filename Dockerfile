FROM ubuntu:22.04 AS base

FROM base AS build

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV RUSTUP_HOME=/usr/local/rustup \
	CARGO_HOME=/usr/local/cargo   \
	PATH=/usr/local/cargo/bin:$PATH

RUN apt-get update && apt-get --no-install-recommends install -y \
	build-essential ca-certificates curl git

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y \
	&& rustup --version                          \
	&& cargo --version                           \
	&& rustc --version

COPY . /app
WORKDIR /app
RUN cargo build --release --bin datadog-static-analyzer
RUN cargo build --release --bin datadog-static-analyzer-git-hook
RUN cargo build --release --bin datadog-static-analyzer-server

FROM base

COPY --from=build /app/target/release/datadog-static-analyzer /usr/bin/datadog-static-analyzer
COPY --from=build /app/target/release/datadog-static-analyzer-server /usr/bin/datadog-static-analyzer-server
COPY --from=build /app/target/release/datadog-static-analyzer-git-hook /usr/bin/datadog-static-analyzer-git-hook
COPY --from=build /app/misc/github-action.sh /usr/bin/github-action.sh

RUN apt update && apt install -y curl git \
	&& curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
	&& apt remove -y nodejs npm \
	&& apt install -y nodejs \
	&& apt clean && rm -rf /var/lib/apt/lists/*
RUN npm install -g @datadog/datadog-ci \
	&& datadog-ci --version            \
	&& datadog-static-analyzer --version

ENTRYPOINT ["/usr/bin/datadog-static-analyzer"]
CMD ["--help"]
