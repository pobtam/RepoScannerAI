#!/usr/bin/env bash
#
# setup.sh — prepare this machine to run the vulnerability framework locally.
#
# Safe to run more than once: it checks what is missing, installs only the
# project's own dependencies, and changes nothing else on your machine. It
# never installs system software — if something is missing it tells you where
# to get it and stops, because a script that silently installs a language
# runtime is a script nobody can reason about.
#
# What it needs: Go and Node.js. Nothing else. No Docker, no database, no
# credentials, no network access to anything but the public package registries.

set -euo pipefail

cd "$(dirname "$0")"

GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
BOLD=$'\033[1m'
PLAIN=$'\033[0m'

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s%s%s\n' "$BOLD" "$*" "$PLAIN"; }
ok()   { printf '%s  ✓ %s%s\n' "$GREEN" "$*" "$PLAIN"; }
fail() { printf '%s  ✕ %s%s\n' "$RED" "$*" "$PLAIN"; }

MISSING=0

step "Checking what this machine already has"

if command -v go >/dev/null 2>&1; then
  ok "Go is installed ($(go version | awk '{print $3}'))"
else
  fail "Go is NOT installed."
  say ""
  say "  The framework's backend is written in Go. Install it from:"
  say "      https://go.dev/dl/"
  say ""
  say "  Download the installer for your operating system, run it, then open a"
  say "  NEW terminal window and run ./setup.sh again."
  MISSING=1
fi

if command -v node >/dev/null 2>&1; then
  ok "Node.js is installed ($(node --version))"
else
  fail "Node.js is NOT installed."
  say ""
  say "  The framework's web interface needs Node.js. Install it from:"
  say "      https://nodejs.org/en/download"
  say ""
  say "  Choose the LTS version, run the installer, then open a NEW terminal"
  say "  window and run ./setup.sh again."
  MISSING=1
fi

if [ "$MISSING" -ne 0 ]; then
  say ""
  say "Setup stopped: install the software listed above first."
  say "Nothing on your machine has been changed."
  exit 1
fi

step "Building the backend"
# Building here rather than at run time so a compile error is reported now,
# with the rest of setup still to do, instead of when someone is waiting for
# the app to start.
(cd vulnframework && go build ./...)
ok "backend builds"

step "Running the backend's own checks"
# A quick subset, not the whole suite: this is a smoke test that the machine
# can actually run the code, and a full run takes minutes.
(cd vulnframework && go vet ./internal/api/ ./internal/demo/ >/dev/null)
ok "backend passes vet"

step "Installing the interface's dependencies"
say "  (this downloads packages from the public npm registry and may take a minute)"
(cd reportui && npm install --no-audit --no-fund --loglevel=error)
ok "interface dependencies installed"

step "Generating the interface's types from the API"
# The interface's TypeScript types are GENERATED from the API's own schema, so
# they cannot drift from the server. That means starting the server briefly.
(
  cd vulnframework
  go run ./cmd/apiserver -demo -addr 127.0.0.1:8099 >/tmp/vulnframework-setup-api.log 2>&1 &
  echo $! > /tmp/vulnframework-setup-api.pid
)
cleanup() {
  if [ -f /tmp/vulnframework-setup-api.pid ]; then
    kill "$(cat /tmp/vulnframework-setup-api.pid)" 2>/dev/null || true
    rm -f /tmp/vulnframework-setup-api.pid
  fi
}
trap cleanup EXIT

# Wait for it, rather than sleeping a fixed time and hoping.
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8099/v1/health >/dev/null 2>&1; then break; fi
  sleep 0.5
done

if ! curl -fsS http://127.0.0.1:8099/v1/health >/dev/null 2>&1; then
  fail "the API server did not start; see /tmp/vulnframework-setup-api.log"
  exit 1
fi

(cd reportui && API_URL=http://127.0.0.1:8099 npm run gen --silent)
ok "interface types generated from the API's schema"

(cd reportui && npm run typecheck --silent)
ok "interface type-checks against the generated types"

cleanup
trap - EXIT

step "Setup complete."
say ""
say "Start the app with:"
say ""
say "    ./run.sh"
say ""
say "It needs no credentials, no database and no internet connection, and it"
say "shows clearly-labelled demonstration data rather than anything real."
