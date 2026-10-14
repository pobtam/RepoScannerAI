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
#     and its value never served.
#
# Run deploy/build.sh first (SKIP_SCANNER=1 deploy/build.sh if the scanner
# image is already built). The stack is stopped at the end; its Docker
# volumes (vf-stacktest_*) are kept, as nothing here deletes volumes.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORK="$(mktemp -d)"
GHFAKE_PID=""
PROJECT=vf-stacktest
U=https://localhost:18443
cleanup() {
  if [ -n "$GHFAKE_PID" ]; then kill "$GHFAKE_PID" 2>/dev/null || true; wait "$GHFAKE_PID" 2>/dev/null || true; fi
  docker compose --env-file "$WORK/env" -p "$PROJECT" -f deploy/compose.yaml down >/dev/null 2>&1 || true
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
HTTP_PORT=18480
HTTPS_PORT=18443
SWEEP_CONCURRENCY=2
VULNFRAMEWORK_GITHUB_API=http://host.docker.internal:18090
EOF

echo "starting the stack ($PROJECT)"
docker compose --env-file "$WORK/env" -p "$PROJECT" -f deploy/compose.yaml up -d >/dev/null 2>&1 || fail "compose up"
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

VF_ENV_FILE="$WORK/env" COMPOSE_PROJECT_NAME="$PROJECT" VULNFRAMEWORK_GITHUB_TOKEN=stacktest-token \
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

echo "STACK OK"
