ARG GO_IMAGE=golang:1.24-bookworm@sha256:1a6d4452c65dea36aac2e2d606b01b4a029ec90cc1ae53890540ce6173ea77ac
ARG RUNTIME_IMAGE=debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe
ARG NODE_IMAGE=node:22-bookworm-slim@sha256:5373f1906319b3a1f291da5d102f4ce5c77ccbe29eb637f072b6c7b70443fc36
ARG PNPM_TRACK=10
ARG YARN_TRACK=4

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS builder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
  go build -trimpath -ldflags='-s -w' -o /out/claw-wrap ./cmd/claw-wrap

FROM ${NODE_IMAGE} AS node-runtime

FROM ${RUNTIME_IMAGE}

ARG PNPM_TRACK
ARG YARN_TRACK

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      bash \
      build-essential \
      ca-certificates \
      curl \
      file \
      git \
      gosu \
      jq \
      procps \
      xz-utils \
    && groupadd --system linuxbrew \
    && useradd --system --create-home --home-dir /home/linuxbrew --gid linuxbrew --shell /bin/bash linuxbrew \
    && mkdir -p /home/linuxbrew/.linuxbrew /opt/claw-wrap-seed \
    && chown -R linuxbrew:linuxbrew /home/linuxbrew \
    && rm -rf /var/lib/apt/lists/*

COPY --from=node-runtime /usr/local/ /usr/local/

RUN su -s /bin/bash - linuxbrew -c 'NONINTERACTIVE=1 CI=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' \
    && tar -C /home/linuxbrew/.linuxbrew -cf /opt/claw-wrap-seed/homebrew.tar . \
    && corepack enable pnpm \
    && rm -f /usr/local/bin/yarn /usr/local/bin/yarnpkg \
    && corepack enable yarn \
    && corepack prepare "pnpm@${PNPM_TRACK}" --activate \
    && corepack prepare "yarn@${YARN_TRACK}" --activate \
    && pnpm --version \
    && yarn --version \
    && rm -rf /root/.npm

COPY --from=builder /out/claw-wrap /usr/local/bin/claw-wrap
COPY docker/claw-wrap/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker/claw-wrap/onboard.sh /usr/local/bin/onboard.sh
COPY docker/claw-wrap/doctor.sh /usr/local/bin/doctor.sh

RUN chmod +x /usr/local/bin/claw-wrap /usr/local/bin/entrypoint.sh /usr/local/bin/onboard.sh /usr/local/bin/doctor.sh \
    && ln -sf /usr/local/bin/doctor.sh /usr/local/bin/doctor \
    && mkdir -p /etc/openclaw /opt/claw-wrap /run/openclaw /home/linuxbrew/.linuxbrew /workspace/config

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
