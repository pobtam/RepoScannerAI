# The deployable images, built from the repository root:
#
#   docker build -f deploy/Dockerfile --target api   -t vulnframework-api:v1   .
#   docker build -f deploy/Dockerfile --target web   -t vulnframework-web:v1   .
#   docker build -f deploy/Dockerfile --target sweep -t vulnframework-sweep:v1 \
#       --build-arg SCANNER_IMAGE=vulnframework-scanner:v1 .
#
# api    the API server and the admin tools (vfctl, orchestrator -migrate),
#        on a distroless base: no shell, no package manager, non-root.
# web    Caddy serving the built interface and fronting the API: HTTPS, the
#        login, and the identity headers the API trusts (deploy/Caddyfile).
# sweep  the orchestrator on top of the pinned scanner image, which already
#        carries every scanner at its tools.lock version. Build the scanner
#        image first (vulnframework/deploy/scanner/Dockerfile); this file does
#        not rebuild it, so the tools a sweep runs are the ones verify-image.sh
#        checked.

ARG GO_VERSION=1.26
ARG SCANNER_IMAGE=vulnframework-scanner:v1

# --- Go programs -------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS gobuild
WORKDIR /src
COPY vulnframework/go.mod vulnframework/go.sum ./
RUN go mod download
COPY vulnframework/ ./
ENV CGO_ENABLED=0
RUN go build -trimpath -ldflags="-s -w" -o /out/apiserver ./cmd/apiserver \
 && go build -trimpath -ldflags="-s -w" -o /out/vfctl ./cmd/vfctl \
 && go build -trimpath -ldflags="-s -w" -o /out/orchestrator ./cmd/orchestrator

# --- the interface -----------------------------------------------------------
FROM node:20-bookworm-slim AS uibuild
WORKDIR /ui
COPY reportui/package.json reportui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY reportui/ ./
RUN npx tsc --noEmit && npx vite build --outDir /out/ui

# --- api ---------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot AS api
COPY --from=gobuild /out/apiserver /out/vfctl /out/orchestrator /usr/local/bin/
COPY vulnframework/config /opt/vf/config
WORKDIR /opt/vf
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/apiserver"]
CMD ["-addr", "0.0.0.0:8080", "-calibration", "/opt/vf/config/calibration.yaml", "-policy", "/opt/vf/config/policy.yaml"]

# --- web ---------------------------------------------------------------------
FROM caddy:2.8.4-alpine AS web
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=uibuild /out/ui /srv

# --- sweep -------------------------------------------------------------------
FROM ${SCANNER_IMAGE} AS sweep
COPY --from=gobuild /out/orchestrator /usr/local/bin/orchestrator
COPY vulnframework/config /opt/vf/config
# Semgrep otherwise reports usage metrics and checks for a newer version.
ENV SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0
USER scanner
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/orchestrator"]
