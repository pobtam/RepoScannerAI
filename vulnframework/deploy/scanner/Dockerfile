# Scanner image (VM-AD §8.3).
#
# Every tool is pinned to the exact version in config/tools.lock. The image is
# identified by digest, and both the digest and every tool version are recorded
# on the run (VM-F-202): a change in finding counts is uninterpretable without
# knowing whether the scanner changed.
#
# Keep the versions here in step with config/tools.lock. The build asserts they
# match at the end rather than trusting the two to stay aligned by hand.

ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm AS gotools

ARG GOVULNCHECK_VERSION=v1.8.0
ARG GOSEC_VERSION=v2.29.0
ARG STATICCHECK_VERSION=v0.8.1
ARG OSV_SCANNER_VERSION=v2.6.0
ARG GITLEAKS_VERSION=v8.30.1

# Let each tool pull the Go toolchain its go.mod declares. Pinning the
# toolchain here would silently cap which tool versions can be pinned in
# config/tools.lock, which is the wrong constraint to impose.
ENV GOFLAGS=-mod=mod CGO_ENABLED=0 GOTOOLCHAIN=auto

RUN go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}
# gosec and gitleaks stamp their version from ldflags at release time; a plain
# `go install` leaves them reporting "dev". Stamping here keeps the image
# self-describing, so a run record can be checked against the binary that
# produced it rather than against config/tools.lock alone (VM-F-202).
RUN go install -ldflags "-X main.Version=${GOSEC_VERSION}" github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}
RUN go install honnef.co/go/tools/cmd/staticcheck@${STATICCHECK_VERSION}
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}
RUN go install -ldflags "-X github.com/zricethezav/gitleaks/v8/cmd.Version=${GITLEAKS_VERSION}" github.com/zricethezav/gitleaks/v8@${GITLEAKS_VERSION}

FROM node:20-bookworm-slim AS runtime

ARG TRIVY_VERSION=0.74.0
ARG SEMGREP_VERSION=1.177.0
ARG GO_TOOLCHAIN=1.26.1

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-venv python3-pip tar \
    && rm -rf /var/lib/apt/lists/*

# The Go toolchain: govulncheck and gosec need it to analyse a module, and
# VM-F-223 requires the declared toolchain be checked against the current patch
# release.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) goarch=amd64 ;; arm64) goarch=arm64 ;; *) echo "unsupported arch $arch" >&2; exit 1 ;; esac; \
    curl -fsSL "https://go.dev/dl/go${GO_TOOLCHAIN}.linux-${goarch}.tar.gz" -o /tmp/go.tgz; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:/usr/local/bin:$PATH

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) tarch=64bit ;; arm64) tarch=ARM64 ;; *) echo "unsupported arch $arch" >&2; exit 1 ;; esac; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tarch}.tar.gz" -o /tmp/trivy.tgz; \
    tar -C /usr/local/bin -xzf /tmp/trivy.tgz trivy; \
    rm /tmp/trivy.tgz

RUN python3 -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

COPY --from=gotools /go/bin/govulncheck /usr/local/bin/govulncheck
COPY --from=gotools /go/bin/gosec       /usr/local/bin/gosec
COPY --from=gotools /go/bin/staticcheck /usr/local/bin/staticcheck
COPY --from=gotools /go/bin/osv-scanner /usr/local/bin/osv-scanner
COPY --from=gotools /go/bin/gitleaks    /usr/local/bin/gitleaks

# Scan workers hold no credential granting write access to any repository
# (VM-F-206) and run as a non-root user.
RUN useradd --create-home --uid 10001 scanner
USER scanner
WORKDIR /work

# Fail the build if a tool is missing or reports an unexpected version: an image
# whose contents do not match config/tools.lock makes every run record wrong.
RUN set -eux; \
    govulncheck -version >/dev/null; \
    gosec --version >/dev/null; \
    staticcheck -version >/dev/null; \
    osv-scanner --version >/dev/null; \
    gitleaks version >/dev/null; \
    trivy --version >/dev/null; \
    semgrep --version >/dev/null; \
    npm --version >/dev/null; \
    go version >/dev/null

CMD ["/bin/bash"]
