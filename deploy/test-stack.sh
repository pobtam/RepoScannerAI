#!/usr/bin/env bash
# deploy/test-stack.sh — run the deployable stack on this machine and prove
# it works, with no real GitHub account, token or repository.
#
# It starts the compose stack under its own project name (vf-stacktest) on
# ports 18480/18443 with a throwaway login, then checks:
#   * the front door refuses no login, a wrong password, and forged identity
#     headers; serves the interface and the API to the login;
#   * the API publishes no port of its own;
#   * a client's own identity headers are overwritten by the proxy's;
#   * a sweep, through the real sweep image, discovers a local fake GitHub
#     account (internal/gh/ghfake), downloads and scans its two fabricated
#     repositories, and records them; the planted test secret is reported
#     and its value never served;
#   * NuGuard, as a local fake in the NuGuard sidecar's place (the worker's
#     network namespace, loopback only): a scan with a NuGuard code finding
#     and an AI inventory; a NuGuard scan that is partial, recorded as a
#     gap; and NuGuard down, recorded as a gap with the scan otherwise
#     complete. The real NuGuard image is not used: see DEPLOY.md.
#
# Run deploy/build.sh first (SKIP_SCANNER=1 deploy/build.sh if the scanner
# image is already built). To test a branch without touching the v1 images a
# running stack uses, build and test under another tag:
#   VF_IMAGE_TAG=branch-test SKIP_SCANNER=1 deploy/build.sh
#   VF_IMAGE_TAG=branch-test deploy/test-stack.sh The test's database lives in memory (tmpfs), so
# each run starts empty and leaves no database volume. The stack is stopped
# at the end; its other Docker
# volumes (vf-stacktest_*) are kept, as nothing here deletes volumes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
GHFAKE_PID=""
PROJECT=vf-stacktest
U=https://localhost:${STACK_HTTPS_PORT:-18543}
cleanup() {
  if [ -n "$GHFAKE_PID" ]; then kill "$GHFAKE_PID" 2>/dev/null || true; wait "$GHFAKE_PID" 2>/dev/null || true; fi
  if [ -f "$WORK/test.override.yaml" ]; then "${COMPOSE[@]}" down >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
fail() { printf 'STACK FAIL: %s\n' "$*" >&2; exit 1; }
ok() { printf '  ok  %s\n' "$*"; }
code() { curl -sk -o /dev/null -w '%{http_code}' "$@"; }

PW="stacktest-$(openssl rand -hex 8)"
HASH="$(docker run --rm caddy:2.8.4-alpine caddy hash-password --plaintext "$PW")"
cat >"$WORK/env" <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 16)
SITE_ADDRESS=localhost
TLS=internal
LOGIN_USER=admin
LOGIN_HASH='$HASH'
HTTP_PORT=${STACK_HTTP_PORT:-18580}
HTTPS_PORT=${STACK_HTTPS_PORT:-18543}
SWEEP_CONCURRENCY=2
VULNFRAMEWORK_GITHUB_API=http://host.docker.internal:18090
NUGUARD_URL=http://127.0.0.1:8085
NUGUARD_API_KEY_SHA256=unused-by-the-fake
EOF
# The fake NuGuard, built for the containers' platform, with its scripted
# answers for octo/go-api: a scan with code findings, then a partial one.
mkdir -p "$WORK/nuguard"
(cd vulnframework && CGO_ENABLED=0 GOOS=linux GOARCH="$(docker version --format '{{.Server.Arch}}')" \
  go build -o "$WORK/nuguard/nuguardfake" ./internal/nuguard/nuguardfake/cmd/nuguardfake)
cp vulnframework/testdata/fixtures/nuguard/ai-code.json vulnframework/testdata/fixtures/nuguard/quickstart-partial.json "$WORK/nuguard/"
# The test's database in memory: a fresh, empty database every run.
cat >"$WORK/test.override.yaml" <<YAML
services:
  db:
    volumes: !reset []
    tmpfs:
      - /var/lib/postgresql/data
  # The fake in the NuGuard sidecar's place: same network namespace, same
  # loopback address, no real NuGuard image.
  nuguard:
    image: caddy:2.8.4-alpine
    entrypoint: ["/fake/nuguardfake", "-addr", "127.0.0.1:8085",
      "-script", "https://github.com/octo/go-api=/fake/ai-code.json",
      "-script", "https://github.com/octo/go-api=/fake/quickstart-partial.json"]
    environment:
      NUGUARD_FAKE_KEY: stacktest-nuguard-key
    volumes: !override
      - $WORK/nuguard:/fake:ro
YAML
export VF_ENV_FILE="$WORK/env" VF_COMPOSE_OVERRIDE="$WORK/test.override.yaml" COMPOSE_PROJECT_NAME="$PROJECT"
COMPOSE=(docker compose --env-file "$WORK/env" -p "$PROJECT" -f deploy/compose.yaml -f "$WORK/test.override.yaml")

echo "starting the stack ($PROJECT)"
"${COMPOSE[@]}" up -d >"$WORK/up.log" 2>&1 || fail "compose up: $(tail -n 5 "$WORK/up.log")"
for _ in $(seq 1 60); do [ "$(code -u "admin:$PW" $U/v1/health)" = "200" ] && break; sleep 1; done

echo "the front door"
[ "$(code $U/)" = "401" ] || fail "the page is served without a login"
[ "$(code $U/v1/health)" = "401" ] || fail "the API is served without a login"
[ "$(code -u admin:wrong $U/v1/health)" = "401" ] || fail "a wrong password is accepted"
[ "$(code -H 'X-Auth-User: mallory' -H 'X-Auth-Level: security_owner' "$U/v1/findings?scope=open")" = "401" ] ||
  fail "forged identity headers get in without a login"
ok "no login, wrong password, forged headers: all 401"
for p in / /findings /github /v1/health "/v1/findings?scope=open" /v1/github; do
  [ "$(code -u "admin:$PW" "$U$p")" = "200" ] || fail "GET $p with the login"
done
ok "the interface, deep links and the API are served to the login"
[ -z "$(docker port "$PROJECT-api-1")" ] || fail "the API publishes a port"
ok "the API publishes no port"
code -u "admin:$PW" -H 'X-Auth-User: mallory' -H 'X-Auth-Level: public' "$U/v1/runs?probe=identity" >/dev/null
sleep 1
docker logs "$PROJECT-api-1" 2>&1 | grep 'filters=probe' | tail -n 1 | grep -q 'principal=admin level=security_owner' ||
  fail "a client's identity headers reached the API"
ok "a client's identity headers are overwritten by the proxy"

echo "a sweep against a local fake GitHub"
mkdir -p "$WORK/repos/octo"
cp -R vulnframework/testdata/repos/go-api vulnframework/testdata/repos/payments-web "$WORK/repos/octo/"
(cd vulnframework && go run ./internal/testkeys/cmd/testkeys expand "$WORK/repos" >/dev/null &&
  go build -o "$WORK/ghfake" ./internal/gh/ghfake/cmd/ghfake)
GHFAKE_TOKEN=stacktest-token "$WORK/ghfake" -addr 127.0.0.1:18090 -base-url http://host.docker.internal:18090 \
  -account octo -repos "$WORK/repos" 2>/dev/null &
GHFAKE_PID=$!
for _ in $(seq 1 20); do curl -s -o /dev/null http://127.0.0.1:18090/user && break; sleep 0.5; done

VULNFRAMEWORK_GITHUB_TOKEN=stacktest-token \
  deploy/sweep.sh >"$WORK/sweep.log" 2>&1 || fail "sweep: $(tail -n 5 "$WORK/sweep.log")"
record="$(ls -t deploy/runs/sweep-*.json | head -n 1)"
python3 - "$record" <<'PY' || fail "the sweep record is wrong"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["discovery"]["account"] == "octo" and d["discovery"]["included"] == 2, d["discovery"]
assert d["sweep"]["Close"]["Produced"] == 2, d["sweep"]["Close"]
PY
rm -f "$record"
ok "discovered 2 repositories, downloaded and scanned both"

curl -sk -u "admin:$PW" "$U/v1/findings?scope=open&category=secret&limit=50" >"$WORK/secrets.json"
grep -q '"secret"' "$WORK/secrets.json" || fail "the planted secret was not reported"
mkdir -p "$WORK/planted"
printf '@@TESTKEY:aws-access-key-id@@' >"$WORK/planted/a"
printf '@@TESTKEY:aws-secret-access-key@@' >"$WORK/planted/b"
(cd vulnframework && go run ./internal/testkeys/cmd/testkeys expand "$WORK/planted" >/dev/null)
for f in "$WORK/planted"/*; do
  if grep -qF "$(cat "$f")" "$WORK/secrets.json"; then fail "a planted credential value was served"; fi
done
ok "planted secret reported, value never served"

echo "administration through deploy/vfctl.sh"
status="$(deploy/vfctl.sh github status 2>/dev/null)"
printf '%s' "$status" | grep -q "octo (fine-grained token)" || fail "vfctl github status: $status"
printf '%s' "$status" | grep -q "2 repositories, 2 to scan" || fail "vfctl github status: $status"
deploy/vfctl.sh repo exclude octo/payments-web -reason "stack test" -as stacktest >/dev/null 2>&1 ||
  fail "vfctl repo exclude"
curl -sk -u "admin:$PW" "$U/v1/github" | grep -q '"stack test"' || fail "the exclusion is not on the GitHub page"
ok "vfctl runs against the stack; an exclusion shows on the GitHub page"

echo "Scan now, through the front door, run by the scan worker"
VULNFRAMEWORK_GITHUB_TOKEN=stacktest-token VULNFRAMEWORK_NUGUARD_API_KEY=stacktest-nuguard-key \
  deploy/scanworker.sh start >"$WORK/worker.log" 2>&1 ||
  fail "starting the scan worker: $(tail -n 5 "$WORK/worker.log")"
csrf="$(curl -sk -u "admin:$PW" "$U/v1/csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
[ "$(code -u "admin:$PW" -X POST -H 'Sec-Fetch-Site: cross-site' -H "X-CSRF-Token: $csrf" \
  -d '{"repo":"octo/go-api"}' "$U/v1/scans")" = "403" ] || fail "a cross-site scan request was accepted"
[ "$(code -u "admin:$PW" -X POST -H 'Sec-Fetch-Site: same-origin' \
  -d '{"repo":"octo/go-api"}' "$U/v1/scans")" = "403" ] || fail "a scan request without a CSRF token was accepted"
[ "$(code -X POST -H 'Sec-Fetch-Site: same-origin' -H "X-CSRF-Token: $csrf" \
  -d '{"repo":"octo/go-api"}' "$U/v1/scans")" = "401" ] || fail "a scan request without a login was accepted"
ok "cross-site, missing CSRF token and no login: all refused"
status="$(code -u "admin:$PW" -X POST -H 'Sec-Fetch-Site: same-origin' -H "X-CSRF-Token: $csrf" \
  -d '{"repo":"octo/go-api"}' "$U/v1/scans")"
[ "$status" = "201" ] || fail "Scan now answered $status"
for _ in $(seq 1 120); do
  st="$(curl -sk -u "admin:$PW" "$U/v1/scans?repo=octo/go-api&limit=1" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["status"])')"
  case "$st" in queued|running) sleep 2 ;; *) break ;; esac
done
[ "$st" = "finished" ] || fail "the requested scan ended $st, want finished: $(curl -sk -u "admin:$PW" "$U/v1/scans?repo=octo/go-api&limit=1")"
ok "Scan now: queued, run by the worker, finished with its run"
docker logs "$PROJECT-api-1" 2>&1 | grep 'path=/v1/scans' | grep 'method=POST' | grep -q 'subject="repo=octo/go-api queued' ||
  fail "the access log has no record of who asked for which repository"
ok "the access log records who asked for which repository"

echo "NuGuard, through the sidecar (a local fake)"
# scan_now asks for a fresh scan of octo/go-api, waits for it to end, and
# prints "status|reason".
scan_now() {
  local csrf st
  csrf="$(curl -sk -u "admin:$PW" "$U/v1/csrf" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
  [ "$(code -u "admin:$PW" -X POST -H 'Sec-Fetch-Site: same-origin' -H "X-CSRF-Token: $csrf" \
    -d '{"repo":"octo/go-api"}' "$U/v1/scans")" = "201" ] || fail "Scan now was not accepted"
  for _ in $(seq 1 120); do
    st="$(curl -sk -u "admin:$PW" "$U/v1/scans?repo=octo/go-api&limit=1" |
      python3 -c 'import json,sys; r=json.load(sys.stdin)[0]; print(r["status"]+"|"+(r.get("reason") or ""))')"
    case "$st" in queued\|*|running\|*) sleep 2 ;; *) break ;; esac
  done
  printf '%s' "$st"
}
ai_measured() {
  curl -sk -u "admin:$PW" "$U/v1/repos/octo/go-api" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["ai_components"]["measured"])'
}
# The scan above took NuGuard's first script: code findings.
curl -sk -u "admin:$PW" "$U/v1/findings?scope=open&repo=octo/go-api&category=code&limit=500" >"$WORK/code.json"
grep -q '"nuguard"' "$WORK/code.json" || fail "no NuGuard code finding was recorded: $(head -c 400 "$WORK/code.json")"
grep -q 'NGA-PROMPT-INJ-001' "$WORK/code.json" || fail "NuGuard's prompt-injection finding is missing"
[ "$(ai_measured)" = "True" ] || fail "the AI inventory was not recorded"
ok "a scan with a NuGuard code finding and an AI inventory"
if grep -q 'stacktest-nuguard-key\|stacktest-token' "$WORK/code.json"; then fail "a credential was served"; fi
ok "neither credential is served"

st="$(scan_now)"
case "$st" in "finished|partial: tool_failed: nuguard/osv"*) ;; *) fail "a partial NuGuard scan ended '$st'" ;; esac
ok "a partial NuGuard scan is a gap: $st"

docker stop "$PROJECT-nuguard-1" >/dev/null
st="$(scan_now)"
case "$st" in "finished|partial: execution_failed: nuguard"*) ;; *) fail "with NuGuard down the scan ended '$st'" ;; esac
[ "$(ai_measured)" = "False" ] || fail "with NuGuard down, the AI inventory still reads as measured"
ok "NuGuard down is a gap, the scan otherwise complete, the inventory not measured: $st"

deploy/scanworker.sh stop >/dev/null 2>&1
[ -z "$(docker ps -q --filter "name=$PROJECT-scanworker")" ] || fail "the scan worker is still running after stop"
[ -z "$(docker ps -aq --filter "name=$PROJECT-nuguard")" ] || fail "the NuGuard sidecar is still there after stop"
ok "stopping the worker removes it and the NuGuard sidecar, and the token and key with them"

echo "STACK OK"
