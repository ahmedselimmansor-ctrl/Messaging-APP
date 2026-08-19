# One Dockerfile for every Go service. SERVICE selects which main package to
# build, so there is one file to keep secure and up to date rather than nine.
#
# The build context is the repository root, because the services share a
# module. Cloud Build passes --build-arg SERVICE=<name> and -f build/Dockerfile.

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
FROM golang:1.26-bookworm AS build

WORKDIR /src

# Copy the module files alone first. Dependencies change far less often than
# source, so this layer is cached across almost every build — the difference
# between a 20-second build and a 3-minute one.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG SERVICE
ARG VERSION=dev
ARG COMMIT=unknown

# CGO off produces a static binary that runs on distroless without a libc.
# -trimpath strips local paths from the binary, which keeps build output
# reproducible and stops the image leaking the build machine's directory
# layout.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    test -n "$SERVICE" || (echo "SERVICE build-arg is required" && exit 1) && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/service \
      ./services/${SERVICE}

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
#
# distroless/static: no shell, no package manager, no libc. A remote code
# execution in the application has nothing to pivot to — no `sh` to spawn, no
# `curl` to fetch a payload. The cost is that debugging needs `kubectl debug`
# with an ephemeral container instead of `kubectl exec`, which is a fair trade.
FROM gcr.io/distroless/static-debian12:nonroot

# nonroot is uid 65532, matching runAsUser in the manifests. They must agree:
# a mismatch means the pod's securityContext overrides the image and any file
# the build created becomes unreadable.
USER 65532:65532

COPY --from=build --chown=65532:65532 /out/service /service

# The admin listener; the public port varies by service and is published by
# the Kubernetes Service.
EXPOSE 9090

ENTRYPOINT ["/service"]
