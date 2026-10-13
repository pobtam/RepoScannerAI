#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end smoke test of the programs a person runs.
#
#   scripts/smoke.sh           the demo: API with demo data, every read
#                              endpoint answers, and the interface builds
#   scripts/smoke.sh --real    also real mode: the scanner image sweeps the
#                              fabricated repositories in testdata/repos into a
#                              THROWAWAY database, then the API serves them
#
# --real never touches the real-mode database (vulnframework-pg, volume
# vulnframework-pgdata) or any real repository. It runs its own Postgres
# container, vf-smoke-pg, whose data lives in a temporary folder that is
# removed afterwards. It needs Docker, the scanner image, and the network the
# scanners need (vulnerability databases, exploitation feeds); nothing it
# does writes anywhere but that temporary database.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VF="$ROOT/vulnframework"
REAL=0
[ "${1:-}" = "--real" ] && REAL=1

PORT="${SMOKE_PORT:-18080}"
WORK="$(mktemp -d)"
API_PID=""
SMOKE_PG=vf-smoke-pg

cleanup() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  if [ "$REAL" -eq 1 ]; then
    # Started with --rm, so stopping it removes the container; its data is
    # the temporary folder below.
    docker stop "$SMOKE_PG" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

fail() { printf 'SMOKE FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf '  ok  %s\n' "$*"; }

# get PATH [HEADERS...] prints the body of a 200 response, or fails.
get() {
  local path="$1"; shift
  local code
  code="$(curl -s -o "$WORK/body" -w '%{http_code}' "$@" "http://127.0.0.1:${PORT}${path}")" || true
  [ "$code" = "200" ] || fail "GET $path answered $code: $(head -c 300 "$WORK/body" 2>/dev/null)"
  cat "$WORK/body"
}

wait_api() {
  for _ in $(seq 1 240); do
    if curl -s -o /dev/null "http://127.0.0.1:${PORT}/v1/health"; then return 0; fi
    kill -0 "$API_PID" 2>/dev/null || fail "the API exited while starting; log: $(tail -n 20 "$WORK/api.log")"
    sleep 0.5
  done
  fail "the API did not start"
}

stop_api() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  wait "$API_PID" 2>/dev/null || true
  API_PID=""
}

echo "building the programs"
(cd "$VF" && go build -o "$WORK/apiserver" ./cmd/apiserver && go build -o "$WORK/vfctl" ./cmd/vfctl) ||
  fail "go build"

# --- demo ----------------------------------------------------------------------
echo "demo"
(cd "$VF" && exec "$WORK/apiserver" -addr "127.0.0.1:${PORT}" -demo -firstparty config/firstparty.demo.yaml) \
  >"$WORK/api.log" 2>&1 &
API_PID=$!
wait_api

for path in /v1/health /v1/runs /v1/runs/latest "/v1/findings?scope=open" "/v1/findings/facets?scope=open" \
  /v1/repos /v1/coverage /v1/waves /v1/metrics/trends /v1/reports /v1/schema/openapi.json; do
  get "$path" >/dev/null
  ok "GET $path"
done
n="$(get '/v1/findings?scope=open&limit=500' | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d.get("findings", d.get("items", []))))')"
[ "$n" -gt 0 ] || fail "the demo serves no findings"
ok "demo serves $n findings"
stop_api

echo "interface build"
(cd "$ROOT/reportui" && npx tsc --noEmit && npx vite build --outDir "$WORK/ui" --emptyOutDir >/dev/null) ||
  fail "the interface does not build"
[ -f "$WORK/ui/index.html" ] || fail "the interface build produced no index.html"
ok "interface builds"

[ "$REAL" -eq 1 ] || { echo "SMOKE OK (demo)"; exit 0; }

# --- real mode, against fabricated repositories ---------------------------------
echo "real mode (throwaway database $SMOKE_PG)"
docker info >/dev/null 2>&1 || fail "--real needs Docker running"
docker ps -a --format '{{.Names}}' | grep -qx "$SMOKE_PG" && fail "$SMOKE_PG already exists; remove it first"

PGPORT="${SMOKE_PG_PORT:-55439}"
mkdir -p "$WORK/pgdata"
export VULNFRAMEWORK_PG_CONTAINER="$SMOKE_PG"
export VULNFRAMEWORK_PG_VOLUME="$WORK/pgdata" # a host folder, not a named volume
export VULNFRAMEWORK_PG_PORT="$PGPORT"
export VULNFRAMEWORK_DSN="postgres://vulnframework:vulnframework@localhost:${PGPORT}/vulnframework?sslmode=disable"
unset ANTHROPIC_API_KEY VULNFRAMEWORK_TRIAGE_MODEL
# shellcheck source=real.sh
. "$ROOT/scripts/real.sh"

real_pg_up >/dev/null || fail "starting $SMOKE_PG"
real_migrate || fail "migrating $SMOKE_PG"
ok "throwaway database migrated"

# The fabricated repositories, with their planted credentials expanded from
# placeholders (internal/testkeys), as the clones folder.
CLONES="$WORK/clones"
mkdir -p "$CLONES"
cp -R "$VF/testdata/repos/." "$CLONES/"
(cd "$VF" && go run ./internal/testkeys/cmd/testkeys expand "$CLONES" >/dev/null)
"$WORK/vfctl" -dsn "$VULNFRAMEWORK_DSN" repo add smoke/go-api -languages go -tier 2 -test-suite >/dev/null
"$WORK/vfctl" -dsn "$VULNFRAMEWORK_DSN" repo add smoke/payments-web -languages javascript -tier 3 -lockfile >/dev/null
ok "fabricated repositories registered"

real_verify_image >/dev/null || fail "the scanner image does not match config/tools.lock"
real_sweep "$CLONES" >"$WORK/sweep.log" 2>&1 || fail "real sweep: $(tail -n 20 "$WORK/sweep.log")"
record="$(ls -t "$VF"/bin/real-runs/sweep-*.json | head -n 1)"
produced="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sweep"]["Close"]["Produced"])' "$record")"
rm -f "$record"
[ "$produced" = "2" ] || fail "the sweep produced $produced scan results, want 2"
ok "sweep scanned both repositories"

(cd "$VF" && exec "$WORK/apiserver" -addr "127.0.0.1:${PORT}" -dsn "$VULNFRAMEWORK_DSN") >"$WORK/api.log" 2>&1 &
API_PID=$!
wait_api
AUTH=(-H 'X-Auth-User: smoke' -H 'X-Auth-Level: security_owner' -H 'X-Auth-Repos: smoke/go-api,smoke/payments-web')
for path in "/v1/findings?scope=open" /v1/repos /v1/coverage /v1/runs/latest; do
  get "$path" "${AUTH[@]}" >/dev/null
  ok "GET $path (real data)"
done
secrets="$(get '/v1/findings?scope=open&category=secret&limit=50' "${AUTH[@]}")"
printf '%s' "$secrets" | grep -q '"secret"' || fail "the planted secret was not reported"
mkdir -p "$WORK/planted"
for name in aws-access-key-id aws-secret-access-key; do
  printf '@@TESTKEY:%s@@' "$name" >"$WORK/planted/$name"
done
(cd "$VF" && go run ./internal/testkeys/cmd/testkeys expand "$WORK/planted" >/dev/null)
for f in "$WORK/planted"/*; do
  if printf '%s' "$secrets" | grep -qF "$(cat "$f")"; then
    fail "a planted credential value was served by the API"
  fi
done
ok "planted secret reported, value never served"
stop_api

echo "SMOKE OK (demo and real mode)"
