#!/usr/bin/env bash
#
# run.sh — start the vulnerability framework on this machine.
#
# By default it runs in DEMONSTRATION mode:
#
#   * the data is fabricated and labelled as such on every screen;
#   * nothing is scanned, no repository is touched, no pull request is opened;
#   * there is no database, no Docker and no credential of any kind;
#   * nothing leaves your machine.
#
# Press Ctrl-C once to stop everything.
#
# Advanced: ./run.sh --postgres runs against a real PostgreSQL database in
# Docker instead of memory. That is for people who want durable storage; the
# demonstration does not need it.

set -euo pipefail

cd "$(dirname "$0")"

BOLD=$'\033[1m'
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
PLAIN=$'\033[0m'

API_PORT="${API_PORT:-8080}"
UI_PORT="${UI_PORT:-5173}"
USE_POSTGRES=0
DSN="${VULNFRAMEWORK_DSN:-postgres://vulnframework:vulnframework@localhost:5433/vulnframework?sslmode=disable}"

for arg in "$@"; do
  case "$arg" in
    --postgres) USE_POSTGRES=1 ;;
    -h|--help)
      sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      printf '%srun.sh: unknown option %s%s\n' "$RED" "$arg" "$PLAIN"
      printf 'Run ./run.sh --help to see the options.\n'
      exit 1
      ;;
  esac
done

if ! command -v go >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
  printf '%sGo and Node.js are needed and one of them is missing.%s\n' "$RED" "$PLAIN"
  printf 'Run ./setup.sh first — it says exactly what to install.\n'
  exit 1
fi

if [ ! -d reportui/node_modules ]; then
  printf '%sThe interface'"'"'s dependencies are not installed.%s\n' "$RED" "$PLAIN"
  printf 'Run ./setup.sh first.\n'
  exit 1
fi

API_PID=""
UI_PID=""
PG_STARTED=0

stop() {
  printf '\nStopping…\n'
  [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null || true
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  if [ "$PG_STARTED" -eq 1 ]; then
    docker stop vulnframework-pg >/dev/null 2>&1 || true
    printf 'The PostgreSQL container is stopped. Its data is kept in the Docker volume\n'
    printf 'vulnframework-pgdata; remove it with: docker volume rm vulnframework-pgdata\n'
  fi
  wait 2>/dev/null || true
  printf 'Stopped.\n'
}
trap stop INT TERM EXIT

API_ARGS=(-addr "127.0.0.1:${API_PORT}" -firstparty config/firstparty.demo.yaml)

if [ "$USE_POSTGRES" -eq 1 ]; then
  if ! command -v docker >/dev/null 2>&1; then
    printf '%s--postgres needs Docker, which is not installed.%s\n' "$RED" "$PLAIN"
    printf 'Install Docker Desktop from https://www.docker.com/products/docker-desktop/\n'
    printf 'or run ./run.sh with no options, which needs no database at all.\n'
    exit 1
  fi
  printf '%sStarting PostgreSQL in Docker…%s\n' "$BOLD" "$PLAIN"
  if ! docker ps --format '{{.Names}}' | grep -q '^vulnframework-pg$'; then
    docker run -d --rm --name vulnframework-pg \
      -e POSTGRES_USER=vulnframework \
      -e POSTGRES_PASSWORD=vulnframework \
      -e POSTGRES_DB=vulnframework \
      -p 5433:5432 \
      -v vulnframework-pgdata:/var/lib/postgresql/data \
      postgres:16-alpine >/dev/null
    PG_STARTED=1
  fi
  printf 'Waiting for the database…\n'
  for _ in $(seq 1 60); do
    if docker exec vulnframework-pg pg_isready -U vulnframework >/dev/null 2>&1; then break; fi
    sleep 1
  done
  if ! docker exec vulnframework-pg pg_isready -U vulnframework >/dev/null 2>&1; then
    printf '%sThe database did not become ready.%s\n' "$RED" "$PLAIN"
    exit 1
  fi
  # The Postgres path serves REAL data, so it refuses to serve an
  # unauthenticated caller: the API requires an authenticating proxy. Running
  # it here is for storage and migration work rather than for browsing, and
  # the messages say so.
  API_ARGS+=(-dsn "$DSN")
  printf '%sNote:%s in --postgres mode the API expects an authenticating proxy to set the\n' "$BOLD" "$PLAIN"
  printf 'identity headers, because the client is never the access control point. The\n'
  printf 'interface will show an authentication error until one is in front of it. The\n'
  printf 'database, the migrations and the API itself are what this mode exercises.\n'
else
  API_ARGS+=(-demo)
fi

printf '%sStarting the API…%s\n' "$BOLD" "$PLAIN"
(cd vulnframework && exec go run ./cmd/apiserver "${API_ARGS[@]}") &
API_PID=$!

for _ in $(seq 1 120); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/v1/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    printf '%sThe API stopped while starting up.%s\n' "$RED" "$PLAIN"
    exit 1
  fi
  sleep 0.5
done

if ! curl -fsS "http://127.0.0.1:${API_PORT}/v1/health" >/dev/null 2>&1; then
  printf '%sThe API did not start in time.%s\n' "$RED" "$PLAIN"
  exit 1
fi
printf '%s  ✓ API ready on port %s%s\n' "$GREEN" "$API_PORT" "$PLAIN"

printf '\n%sApp running — open http://localhost:%s in your browser%s\n\n' "$BOLD" "$UI_PORT" "$PLAIN"
printf 'Press Ctrl-C to stop.\n\n'

cd reportui
PORT="$UI_PORT" API_URL="http://127.0.0.1:${API_PORT}" exec npm run dev -- --host 127.0.0.1 --port "$UI_PORT" --strictPort
