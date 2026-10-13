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
#
# Real repositories: ./run.sh --real ~/clones scans the repositories you
# registered with ./vfctl.sh, from their clones in ~/clones (mounted
# read-only), stores the results in PostgreSQL, and opens the interface on
# them with LOCAL AUTH ON — see REAL-REPOS.md first. Add --no-sweep to browse
# the last results without scanning again. Nothing is written to GitHub.

set -euo pipefail

cd "$(dirname "$0")"

BOLD=$'\033[1m'
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
PLAIN=$'\033[0m'

API_PORT="${API_PORT:-8080}"
UI_PORT="${UI_PORT:-5173}"
USE_POSTGRES=0
USE_REAL=0
REAL_SWEEP=1
CLONES="${VULNFRAMEWORK_CLONES:-}"
DSN="${VULNFRAMEWORK_DSN:-postgres://vulnframework:vulnframework@localhost:5433/vulnframework?sslmode=disable}"

for arg in "$@"; do
  case "$arg" in
    --postgres) USE_POSTGRES=1 ;;
    --real) USE_REAL=1 ;;
    --no-sweep) REAL_SWEEP=0 ;;
    -h|--help)
      awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
      exit 0
      ;;
    -*)
      printf '%srun.sh: unknown option %s%s\n' "$RED" "$arg" "$PLAIN"
      printf 'Run ./run.sh --help to see the options.\n'
      exit 1
      ;;
    *)
      if [ "$USE_REAL" -eq 1 ] && [ -z "${CLONES_SET:-}" ]; then
        CLONES="$arg"
        CLONES_SET=1
      else
        printf '%srun.sh: unexpected argument %s%s\n' "$RED" "$arg" "$PLAIN"
        exit 1
      fi
      ;;
  esac
done

if [ "$USE_REAL" -eq 1 ] && [ "$USE_POSTGRES" -eq 1 ]; then
  printf '%s--real already uses PostgreSQL; drop --postgres.%s\n' "$RED" "$PLAIN"
  exit 1
fi
if [ "$USE_REAL" -eq 0 ] && [ "$REAL_SWEEP" -eq 0 ]; then
  printf '%s--no-sweep only applies with --real.%s\n' "$RED" "$PLAIN"
  exit 1
fi

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
    docker stop "${REAL_PG_NAME:-vulnframework-pg}" >/dev/null 2>&1 || true
    printf 'The PostgreSQL container is stopped. Its data is kept in the Docker volume\n'
    printf '%s; remove it with: docker volume rm %s\n' "${REAL_PG_VOLUME:-vulnframework-pgdata}" "${REAL_PG_VOLUME:-vulnframework-pgdata}"
  fi
  wait 2>/dev/null || true
  printf 'Stopped.\n'
}
trap stop INT TERM EXIT

API_ARGS=(-addr "127.0.0.1:${API_PORT}")

if [ "$USE_REAL" -eq 1 ]; then
  # shellcheck source=scripts/real.sh
  source scripts/real.sh
  real_need_docker || exit 1
  printf '%sStarting PostgreSQL in Docker…%s\n' "$BOLD" "$PLAIN"
  PG_STARTED="$(real_pg_up)" || exit 1
  real_migrate || exit 1

  REAL_REPOS="$(real_active_repos)"
  if [ -z "$REAL_REPOS" ]; then
    printf '%sNo repositories are registered yet.%s Register each clone first, e.g.:\n' "$RED" "$PLAIN"
    printf '  ./vfctl.sh repo add your-org/api -languages go -tier 1 -test-suite\n'
    printf '  ./vfctl.sh repo add your-org/web -languages javascript -lockfile\n'
    printf 'then run ./run.sh --real again. See REAL-REPOS.md.\n'
    exit 1
  fi

  if [ "$REAL_SWEEP" -eq 1 ]; then
    if [ -z "$CLONES" ]; then
      printf '%s--real needs the folder holding your clones:%s ./run.sh --real ~/clones\n' "$RED" "$PLAIN"
      printf '(or ./run.sh --real --no-sweep to browse the last results).\n'
      exit 1
    fi
    if [ ! -d "$CLONES" ]; then
      printf '%s%s is not a folder.%s\n' "$RED" "$CLONES" "$PLAIN"
      exit 1
    fi
    CLONES="$(cd "$CLONES" && pwd)"
    # A stale image is reported, never rebuilt here: every run records the
    # tool versions it used, and a record that does not match the binaries
    # is wrong rather than merely old.
    real_verify_image || exit 1
    real_sweep "$CLONES" || exit 1
  fi

  API_ARGS+=(-dsn "$REAL_DSN")
  if [ -f "$REAL_FIRSTPARTY" ]; then
    API_ARGS+=(-firstparty config/firstparty.yaml)
  fi
elif [ "$USE_POSTGRES" -eq 1 ]; then
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
  API_ARGS+=(-firstparty config/firstparty.demo.yaml)
else
  API_ARGS+=(-demo -firstparty config/firstparty.demo.yaml)
fi

printf '%sStarting the API…%s\n' "$BOLD" "$PLAIN"
(cd vulnframework && exec go run ./cmd/apiserver "${API_ARGS[@]}") &
API_PID=$!

# The API is up when /v1/health answers. With a database it answers 401 to
# this anonymous probe — it serves real data only to an authenticated caller —
# and a 401 is as good a sign of life as a 200. /v1/health itself stays
# authenticated.
api_up() {
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${API_PORT}/v1/health" 2>/dev/null || true)"
  [ "$code" = "200" ] || [ "$code" = "401" ]
}

for _ in $(seq 1 120); do
  if api_up; then break; fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    printf '%sThe API stopped while starting up.%s\n' "$RED" "$PLAIN"
    exit 1
  fi
  sleep 0.5
done

if ! api_up; then
  printf '%sThe API did not start in time.%s\n' "$RED" "$PLAIN"
  exit 1
fi
printf '%s  ✓ API ready on port %s%s\n' "$GREEN" "$API_PORT" "$PLAIN"

printf '\n%sApp running — open http://localhost:%s in your browser%s\n\n' "$BOLD" "$UI_PORT" "$PLAIN"
printf 'Press Ctrl-C to stop.\n\n'

cd reportui
if [ "$USE_REAL" -eq 1 ]; then
  # Local auth: the dev server tells the API you are the security owner. It
  # refuses to start unless bound to 127.0.0.1, and prints a warning banner.
  # Any program on this machine that can reach the port gets the same access.
  export VULNFRAMEWORK_LOCAL_AUTH=1
  VULNFRAMEWORK_LOCAL_AUTH_REPOS="$(printf '%s' "$REAL_REPOS" | paste -sd, -)"
  export VULNFRAMEWORK_LOCAL_AUTH_REPOS
fi
PORT="$UI_PORT" API_URL="http://127.0.0.1:${API_PORT}" exec npm run dev -- --host 127.0.0.1 --port "$UI_PORT" --strictPort
