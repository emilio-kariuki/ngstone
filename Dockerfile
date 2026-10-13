# syntax=docker/dockerfile:1

# Container image for the ngstone edge server (ngstoned). See
# deploy/docker/compose.yaml for a ready-to-run configuration.
#
#   docker build -t ngstoned .
#   docker buildx build --platform linux/amd64,linux/arm64 -t ngstoned .
#
# The builder always runs on the build host's platform and cross-compiles for
# the target, so multi-arch builds need no QEMU emulation.

FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS build

WORKDIR /src

# Module downloads get their own layer, rebuilt only when go.mod or go.sum
# changes.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN --mount=type=cache,target=/root/.cache/go-build \
    GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X ngstone/internal/version.Version=$VERSION -X ngstone/internal/version.Commit=$COMMIT -X ngstone/internal/version.Date=$DATE" \
      -o /out/ngstoned ./cmd/ngstoned

# An empty directory to copy into the runtime image as /data with nonroot
# ownership. Docker seeds a new named volume from the image's directory, so a
# volume mounted at /data starts out writable by uid 65532.
RUN mkdir -p /out/data && chmod 0700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/ngstoned /ngstoned
COPY --from=build --chown=65532:65532 /out/data /data

USER 65532:65532

# Inside the container the edge listens on unprivileged ports, so it needs no
# added capabilities; publish them on the host as 80, 443 and 4443:
#   8080  HTTP to HTTPS redirect (-http :8080)
#   8443  public HTTPS (-public :8443)
#   4443  agent control connections (-control :4443)
# The ops endpoint (/healthz, expvar, pprof) stays on loopback, 127.0.0.1:4041.
EXPOSE 8080 8443 4443

# /healthz answers 200 only once both the apex and wildcard certificates are
# loaded, so the start period allows for the first DNS-01 issuance. The probe
# needs the ops endpoint on 127.0.0.1:4041 (the default); set
# NGSTONE_HEALTHCHECK_URL if -ops is moved.
HEALTHCHECK --interval=30s --timeout=5s --start-period=3m --start-interval=5s --retries=3 \
  CMD ["/ngstoned", "healthcheck"]

ENTRYPOINT ["/ngstoned"]
