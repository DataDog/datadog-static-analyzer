# Docker Container

`datadog-static-analyzer` is available for use in a Docker container. The
container is published to the [GHCR registry](https://github.com/DataDog/datadog-static-analyzer/pkgs/container/datadog-static-analyzer).

## Requirements

- [Docker](https://docs.docker.com/get-docker/)
- An x86_64 or arm64 machine

## Setup

First, pull the container image:

```sh
docker pull ghcr.io/datadog/datadog-static-analyzer:latest
```

Then, run the container to verify that it works:

```sh
docker run ghcr.io/datadog/datadog-static-analyzer:latest --help
```

## Usage

The container can be run in the same way as the binary. For example, to
run the analyzer on a directory stored at `$PATH_TO_ANALYZE`:

```sh
docker run -v $PATH_TO_ANALYZE:/data ghcr.io/datadog/datadog-static-analyzer:latest -i /data -o /data/output.sarif -b -f sarif
```

### Using datadog-ci

The `datadog-ci` tool is also available in the container, and can be used to
upload your results to the Datadog app. To use it, run the container with the
`datadog-ci` command by overriding the entrypoint:

```sh
docker run --entrypoint datadog-ci ghcr.io/datadog/datadog-static-analyzer:latest --help
```

## Building the container from source

To build the container from source, clone the repository and run the following:

```sh
docker build -t datadog-static-analyzer .
```

Then, run the locally-built container:

```sh
docker run datadog-static-analyzer --help
```

## Pinning the container

If you are interested in pinning the container to a specific version, each release
is tagged with the version name as well. For example, to use version `0.3.5`:

```sh
docker pull ghcr.io/datadog/datadog-static-analyzer:0.3.5
```

## Issues

If you encounter any issues, please open an issue [here](https://github.com/DataDog/datadog-static-analyzer/issues/new?assignees=&labels=&projects=&template=bug_report.md&title=).
