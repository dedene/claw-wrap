# syntax=docker/dockerfile:1
#
# Minimal claw-wrap image: the daemon for a sidecar container, and the source
# of the client binary for the agent container.
#
#   docker build -t claw-wrap .
#
# Add the tools you want to broker in a derived image:
#
#   FROM ghcr.io/dedene/claw-wrap:<version>
#   COPY --from=<build-stage> /out/mytool /usr/local/bin/mytool
#
# See docs/KUBERNETES.md.

ARG GO_VERSION=1.26
ARG DEBIAN_RELEASE=trixie

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-${DEBIAN_RELEASE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/claw-wrap ./cmd/claw-wrap

FROM debian:${DEBIAN_RELEASE}-slim

# tini runs as PID 1 so detached daemons started by wrapped tools (which get
# reparented to PID 1 when their parent exits) are reaped instead of lingering
# as zombies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

# A real passwd entry gives wrapped tools a sane HOME and USER.
ARG UID=10001
ARG GID=10001
RUN groupadd --gid ${GID} claw \
    && useradd --uid ${UID} --gid ${GID} --home-dir /var/lib/claw-wrap --create-home --shell /usr/sbin/nologin claw \
    && install -d -o claw -g claw -m 0700 /run/openclaw

COPY --from=build /out/claw-wrap /usr/local/bin/claw-wrap

USER ${UID}:${GID}
WORKDIR /var/lib/claw-wrap
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/claw-wrap"]
CMD ["daemon"]
