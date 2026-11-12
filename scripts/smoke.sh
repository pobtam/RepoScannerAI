#!/usr/bin/env bash
# scripts/smoke.sh — end-to-end smoke test of the programs a person runs.
#
#   scripts/smoke.sh           the demo: API with demo data, every read
#                              endpoint answers, and the interface builds
#   scripts/smoke.sh --real    also real mode: the scanner image sweeps the
#                              fabricated repositories in testdata/repos into a
#                              THROWAWAY database, then the API serves them
#   scripts/smoke.sh --real --nuguard-fake
#                              real mode with NuGuard on, as run.sh --real
#                              --nuguard runs it, but against the fake NuGuard
#                              (nuguardfake) on this Mac's loopback: no
#                              network, no NuGuard install. Adds two clones
#                              with a made-up github.com origin, one whose
#                              commit the fake says GitHub does not have
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
NUGUARD_FAKE=0
for arg in "$@"; do
  case "$arg" in
    --real) REAL=1 ;;
    --nuguard-fake) NUGUARD_FAKE=1 ;;
    *) echo "smoke.sh: unknown option $arg" >&2; exit 2 ;;
  esac
done
if [ "$NUGUARD_FAKE" -eq 1 ] && [ "$REAL" -eq 0 ]; then
  echo "smoke.sh: --nuguard-fake needs --real" >&2
  exit 2
fi

PORT="${SMOKE_PORT:-18080}"
WORK="$(mktemp -d)"
API_PID=""
FAKE_PID=""
SMOKE_PG=vf-smoke-pg

cleanup() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  if [ -n "$FAKE_PID" ]; then
    kill "$FAKE_PID" 2>/dev/null || true
    wait "$FAKE_PID" 2>/dev/null || true
  fi
  if [ "$REAL" -eq 1 ]; then
    docker stop vf-smoke-worker >/dev/null 2>&1 || true
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
  /v1/repos /v1/coverage /v1/waves /v1/metrics/trends /v1/reports /v1/github /v1/schema/openapi.json; do
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
if [ "$NUGUARD_FAKE" -eq 1 ]; then
  # The fake NuGuard on this Mac's loopback, reached from the containers
  # through the same bridge as the real one. Its key is made here, for this
  # run only. The fixture repositories it answers for are made up.
  NG_PORT="${SMOKE_NUGUARD_PORT:-18095}"
  NG_ORIGIN=https://github.com/smoke-fixture
  (cd "$VF" && go build -o "$WORK/nuguardfake" ./internal/nuguard/nuguardfake/cmd/nuguardfake) || fail "go build nuguardfake"
  VULNFRAMEWORK_NUGUARD_API_KEY="smoke-$(openssl rand -hex 16)"
  export VULNFRAMEWORK_NUGUARD_API_KEY REAL_NUGUARD=1 REAL_NUGUARD_PORT="$NG_PORT"
  unset VULNFRAMEWORK_GITHUB_TOKEN
  NUGUARD_FAKE_KEY="$VULNFRAMEWORK_NUGUARD_API_KEY" "$WORK/nuguardfake" -addr "127.0.0.1:$NG_PORT" -narrow \
    -script "$NG_ORIGIN/agent-app=$VF/testdata/fixtures/nuguard/ai-code.json" \
    -script "$NG_ORIGIN/agent-unpushed=error:ref_not_found" >"$WORK/nuguardfake.log" 2>&1 &
  FAKE_PID=$!
fi
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
if [ "$NUGUARD_FAKE" -eq 1 ]; then
  # Two clones with a github.com origin, as git would leave them.
  for name in agent-app agent-unpushed; do
    cp -R "$VF/testdata/repos/payments-web" "$CLONES/$name"
    ( cd "$CLONES/$name"
      export GIT_CONFIG_NOSYSTEM=1 HOME="$WORK" GIT_AUTHOR_NAME=smoke GIT_AUTHOR_EMAIL=smoke@example.invalid \
        GIT_COMMITTER_NAME=smoke GIT_COMMITTER_EMAIL=smoke@example.invalid
      git init -q && git add -A && git commit -q -m fixture && git remote add origin "$NG_ORIGIN/$name.git" ) ||
      fail "making the $name fixture clone"
    "$WORK/vfctl" -dsn "$VULNFRAMEWORK_DSN" repo add "smoke/$name" -languages javascript -tier 3 -lockfile >/dev/null
  done
fi
ok "fabricated repositories registered"

real_verify_image >/dev/null || fail "the scanner image does not match config/tools.lock"
real_sweep "$CLONES" >"$WORK/sweep.log" 2>&1 || fail "real sweep: $(tail -n 20 "$WORK/sweep.log")"
record="$(ls -t "$VF"/bin/real-runs/sweep-*.json | head -n 1)"
produced="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["sweep"]["Close"]["Produced"])' "$record")"
rm -f "$record"
if [ "$NUGUARD_FAKE" -eq 1 ]; then
  [ "$produced" = "4" ] || fail "the sweep produced $produced scan results, want 4"
  ok "sweep scanned all four repositories"
else
  [ "$produced" = "2" ] || fail "the sweep produced $produced scan results, want 2"
  ok "sweep scanned both repositories"
fi

(cd "$VF" && exec "$WORK/apiserver" -addr "127.0.0.1:${PORT}" -dsn "$VULNFRAMEWORK_DSN") >"$WORK/api.log" 2>&1 &
API_PID=$!
wait_api
AUTH=(-H 'X-Auth-User: smoke' -H 'X-Auth-Level: security_owner' -H 'X-Auth-Repos: smoke/go-api,smoke/payments-web')
[ "$NUGUARD_FAKE" -eq 0 ] ||
  AUTH=(-H 'X-Auth-User: smoke' -H 'X-Auth-Level: security_owner' -H 'X-Auth-Repos: smoke/go-api,smoke/payments-web,smoke/agent-app,smoke/agent-unpushed')
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

# Every finding says what the problem is, and real scans supply the tool's own
# words for most of them rather than leaving all of them to the fallback.
described="$(get '/v1/findings?scope=open&limit=500' "${AUTH[@]}" | python3 -c '
import json, sys
fs = json.load(sys.stdin)["findings"]
bare = [f["fingerprint"] for f in fs if not f.get("restricted") and not f.get("description")]
tool = sum(1 for f in fs if f.get("description_source") not in (None, "", "derived"))
print(len(fs), tool, " ".join(bare[:5]))')"
read -r total by_tool bare <<<"$described"
[ -z "$bare" ] || fail "findings with no description: $bare"
[ "$by_tool" -gt 0 ] || fail "none of $total findings carries a scanner's description"
ok "every finding described ($by_tool of $total in the scanner's own words)"

if [ "$NUGUARD_FAKE" -eq 1 ]; then
  get /v1/coverage "${AUTH[@]}" >"$WORK/coverage.json"
  python3 - "$WORK/coverage.json" <<'PY' || fail "NuGuard coverage: $(cat "$WORK/coverage.json" | head -c 600)"
import json, sys
c = json.load(open(sys.argv[1]))
nr = {r["repo"]: r["tools"] for r in c["not_requested"]}
for repo in ("smoke/go-api", "smoke/payments-web"):
    tools = nr.get(repo, [])
    assert any(t["tool"] == "nuguard" and t["reason"] == "no GitHub origin; NuGuard needs the repository on GitHub" for t in tools), (repo, tools)
gaps = [g for g in c["gaps"] if g["repo"] == "smoke/agent-unpushed"]
assert any(g.get("cause") == "commit_not_on_github" and g.get("owner") == "repo" and "not on GitHub" in g.get("detail", "") for g in gaps), gaps
for g in c["gaps"]:
    if g["repo"] == "smoke/agent-app":
        assert not any(t.startswith("nuguard") for t in g.get("tools_failed") or []), ("agent-app lost NuGuard", g)
        assert "nuguard" in (g.get("tools_ok") or []), ("agent-app: NuGuard did not run", g)
PY
  ok "no GitHub origin: NuGuard not requested, with the reason; an unpushed commit: the repository's gap"

  n="$(get '/v1/findings?scope=open&repo=smoke/agent-app&found_by=nuguard' "${AUTH[@]}" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))')"
  [ "$n" -gt 0 ] || fail "the clone with a GitHub origin has no NuGuard findings"
  get /v1/repos/smoke/agent-app "${AUTH[@]}" | python3 -c '
import json, sys
a = json.load(sys.stdin)["ai_components"]
assert a["measured"] and a["source"].startswith("nuguard "), a' || fail "no AI inventory for smoke/agent-app"
  get /v1/repos/smoke/agent-app/nuguard "${AUTH[@]}" | python3 -c '
import json, sys
e = json.load(sys.stdin)["recent"][0].get("effective") or {}
assert e.get("enabled") and e.get("tools"), e' || fail "smoke/agent-app recorded no effective NuGuard options"
  ok "GitHub origin: $n NuGuard findings, the AI inventory and the options it ran with"
fi

# Scan now, as ./run.sh --real runs it: a worker over the clones, and a
# request through the API with its same-origin and CSRF checks.
export VULNFRAMEWORK_WORKER_CONTAINER=vf-smoke-worker
real_worker_start "$CLONES" >"$WORK/worker.log" 2>&1 || fail "starting the scan worker: $(tail -n 5 "$WORK/worker.log")"
token="$(get /v1/csrf "${AUTH[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
code="$(curl -s -o "$WORK/body" -w '%{http_code}' "${AUTH[@]}" -X POST -H 'Sec-Fetch-Site: same-origin' \
  -H "X-CSRF-Token: $token" -d '{"repo":"smoke/go-api"}' "http://127.0.0.1:${PORT}/v1/scans")"
[ "$code" = "201" ] || fail "Scan now answered $code: $(cat "$WORK/body")"
for _ in $(seq 1 150); do
  state="$(get '/v1/scans?repo=smoke/go-api&limit=1' "${AUTH[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["status"])')"
  case "$state" in queued|running) sleep 2 ;; *) break ;; esac
done
real_worker_stop
[ "$state" = "finished" ] || fail "the requested scan ended $state: $(get '/v1/scans?repo=smoke/go-api&limit=1' "${AUTH[@]}")"
ok "Scan now: queued, run by the local worker over the clones, finished"
stop_api

if [ "$NUGUARD_FAKE" -eq 1 ]; then
  echo "SMOKE OK (demo and real mode, with the fake NuGuard)"
else
  echo "SMOKE OK (demo and real mode)"
fi
