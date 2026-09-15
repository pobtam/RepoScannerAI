#!/usr/bin/env bash
# Capture scanner fixtures from the pinned scanner image (VM-AD §17 Phase 3).
#
# Fixtures are real captured tool output, not hand-authored approximations. Each
# capture records the tool version that produced it in a sidecar .meta.json, so
# a golden can never be read without knowing which build it came from.
#
# Three envelopes are captured per tool where the tool can produce them:
#   normal — the synthetic repository, which contains deliberate defects
#   empty  — a clean tree, so "no findings" is covered as a shape
#   error  — the tool's own failure envelope, so a broken scan is distinguishable
#            from a clean one (VM-F-204, VM-F-205)
#
# Usage: testdata/capture.sh [image]
set -euo pipefail

IMAGE="${1:-vulnframework-scanner:v1}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/testdata/fixtures"
REPOS="$ROOT/testdata/repos"

echo "capturing from $IMAGE"

docker run --rm \
  -v "$REPOS:/repos:ro" \
  -v "$FIXTURES:/fixtures" \
  -w /tmp \
  "$IMAGE" bash -euo pipefail -c '
set +e
cp -r /repos /tmp/src
GO=/tmp/src/go-api
WEB=/tmp/src/payments-web
mkdir -p /tmp/empty-go/cmd /tmp/empty-web

# A clean Go module, for the empty envelope.
cat > /tmp/empty-go/go.mod <<EOF
module example.com/clean

go 1.24
EOF
cat > /tmp/empty-go/cmd/main.go <<EOF
package main

func main() {}
EOF

# A clean JS project, for the empty envelope.
cat > /tmp/empty-web/package.json <<EOF
{"name":"clean","version":"1.0.0","private":true,"dependencies":{}}
EOF
(cd /tmp/empty-web && npm install --package-lock-only --no-audit --no-fund >/dev/null 2>&1)

# A deliberately broken tree, for the error envelope.
mkdir -p /tmp/broken-go
cat > /tmp/broken-go/go.mod <<EOF
module example.com/broken

go 1.24
EOF
echo "package main; func main() { this is not go" > /tmp/broken-go/main.go

meta() { # meta <fixture-basename> <tool> <version-command>
  local base="$1" tool="$2" version="$3"
  printf "{\n  \"tool\": \"%s\",\n  \"tool_version\": \"%s\",\n  \"image\": \"%s\",\n  \"captured_from\": \"%s\"\n}\n" \
    "$tool" "$version" "'"$IMAGE"'" "$base" > "/fixtures/$tool/$base.meta.json"
}

GOVULN_V=$(govulncheck -version 2>&1 | grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" | head -1)
GOSEC_V=$(gosec --version 2>&1 | grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" | head -1)
STATIC_V=$(staticcheck -version 2>&1 | grep -oE "\(v?[0-9.]+\)" | tr -d "()")
OSV_V=$(osv-scanner --version 2>&1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
GITLEAKS_V="'"$(grep -E '^tool +gitleaks' "$ROOT/config/tools.lock" | awk '{print $3}')"'"
TRIVY_V=$(trivy --version 2>&1 | grep -oE "[0-9]+\.[0-9]+\.[0-9]+" | head -1)
SEMGREP_V=$(semgrep --version 2>&1 | tail -1)
NPM_V=$(npm --version)

cap() { # cap <tool> <name> <version> <dir> <command...>
  local tool="$1" name="$2" version="$3" dir="$4"; shift 4
  mkdir -p "/fixtures/$tool"
  ( cd "$dir" && "$@" ) > "/fixtures/$tool/$name.json" 2>/tmp/$tool-$name.err
  local code=$?
  meta "$name" "$tool" "$version"
  echo "  $tool/$name  exit=$code  bytes=$(wc -c < /fixtures/$tool/$name.json)"
}

echo "govulncheck"
cap govulncheck go-api      "$GOVULN_V" "$GO"           govulncheck -json ./...
cap govulncheck empty       "$GOVULN_V" /tmp/empty-go   govulncheck -json ./...
cap govulncheck error       "$GOVULN_V" /tmp/broken-go  govulncheck -json ./...

echo "gosec"
cap gosec go-api  "$GOSEC_V" "$GO"          gosec -fmt=json -severity=medium -confidence=medium ./...
cap gosec empty   "$GOSEC_V" /tmp/empty-go  gosec -fmt=json -severity=medium -confidence=medium ./...
cap gosec error   "$GOSEC_V" /tmp/broken-go gosec -fmt=json -severity=medium -confidence=medium ./...

echo "staticcheck"
cap staticcheck go-api "$STATIC_V" "$GO"          staticcheck -f json ./...
cap staticcheck empty  "$STATIC_V" /tmp/empty-go  staticcheck -f json ./...
cap staticcheck error  "$STATIC_V" /tmp/broken-go staticcheck -f json ./...

echo "osv-scanner"
cap osv-scanner go-api       "$OSV_V" "$GO"          osv-scanner --format json --recursive .
cap osv-scanner payments-web "$OSV_V" "$WEB"         osv-scanner --format json --recursive .
cap osv-scanner empty        "$OSV_V" /tmp/empty-go  osv-scanner --format json --recursive .
cap osv-scanner error        "$OSV_V" /tmp/nonexistent-path osv-scanner --format json --recursive .

echo "gitleaks"
( cd "$GO" && gitleaks detect --no-git --report-format json --report-path /fixtures/gitleaks/go-api.json ) >/dev/null 2>&1
meta go-api gitleaks "$GITLEAKS_V"; echo "  gitleaks/go-api  bytes=$(wc -c < /fixtures/gitleaks/go-api.json)"
( cd /tmp/empty-go && gitleaks detect --no-git --report-format json --report-path /fixtures/gitleaks/empty.json ) >/dev/null 2>&1
meta empty gitleaks "$GITLEAKS_V"; echo "  gitleaks/empty   bytes=$(wc -c < /fixtures/gitleaks/empty.json)"

echo "trivy"
cap trivy go-api "$TRIVY_V" "$GO"          trivy config --format json --quiet .
cap trivy empty  "$TRIVY_V" /tmp/empty-go  trivy config --format json --quiet .

echo "semgrep"
cap semgrep payments-web "$SEMGREP_V" "$WEB"        semgrep --json --quiet --config p/javascript --config p/typescript .
cap semgrep empty        "$SEMGREP_V" /tmp/empty-web semgrep --json --quiet --config p/javascript .

echo "npm-audit"
cap npm-audit payments-web "$NPM_V" "$WEB"          npm audit --json
cap npm-audit empty        "$NPM_V" /tmp/empty-web  npm audit --json
cap npm-audit error        "$NPM_V" /tmp/broken-go  npm audit --json
cp "$WEB/package.json" /fixtures/npm-audit/package.json
'

echo "capture complete"
