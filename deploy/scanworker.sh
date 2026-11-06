#!/usr/bin/env bash
# deploy/scanworker.sh start|stop|status — the scan worker.
#
# The worker runs the scans requested from the interface ("Scan now", "Scan
# all included repositories"), from vfctl, and by the daily timer. It is the
# only part of the stack that holds the GitHub token.
#
#   start   reads $VULNFRAMEWORK_GITHUB_TOKEN once, now, and starts the worker
#           with it. The token then stays in the worker container's
#           environment for as long as it runs; anyone who can run
#           `docker inspect` on this machine can read it. Use a read-only,
#           expiring, fine-grained token.
#   stop    stops the worker and removes it, and the token with it. Requests
#           it was running are marked interrupted, and can be retried.
#   status  whether it is running.
#
# NuGuard (DEPLOY.md, "NuGuard"): when the settings file sets NUGUARD_URL,
# start also needs $VULNFRAMEWORK_NUGUARD_API_KEY, read once, now, and held
# in the worker's environment exactly as the token is (docker inspect can
# read it); the NuGuard sidecar starts and stops with the worker. With
# NUGUARD_URL empty, nothing about the worker changes.
#
# On the GCP VM, systemd runs this as vulnframework-scanworker.service with
# the token read from Secret Manager; stop it with
#   sudo systemctl stop vulnframework-scanworker
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files=(-f "$ROOT/deploy/compose.yaml")
[ -n "${VF_COMPOSE_OVERRIDE:-}" ] && files+=(-f "$VF_COMPOSE_OVERRIDE")
env_file="${VF_ENV_FILE:-$ROOT/deploy/.env}"
compose=(docker compose --env-file "$env_file" "${files[@]}" --profile worker --profile nuguard)

# nuguard_on: the settings file asks for NuGuard.
nuguard_on() { grep -Eq '^NUGUARD_URL=.+' "$env_file" 2>/dev/null; }
services=(scanworker)
if nuguard_on; then services+=(nuguard); fi
need_nuguard_key() {
  if nuguard_on && [ -z "${VULNFRAMEWORK_NUGUARD_API_KEY:-}" ]; then
    echo "NUGUARD_URL is set in $env_file, so VULNFRAMEWORK_NUGUARD_API_KEY must be set too" >&2
    echo "(the key from: nuguard serve keygen --id vulnframework)." >&2
    exit 1
  fi
  export VULNFRAMEWORK_NUGUARD_API_KEY="${VULNFRAMEWORK_NUGUARD_API_KEY:-}"
}

case "${1:-}" in
  start)
    if [ -z "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then
      echo "VULNFRAMEWORK_GITHUB_TOKEN is not set. Use a fine-grained token with only" >&2
      echo "Contents: read-only and Metadata: read-only." >&2
      exit 1
    fi
    export VULNFRAMEWORK_GITHUB_TOKEN
    need_nuguard_key
    "${compose[@]}" up -d "${services[@]}"
    echo "scan worker started; it holds the token until: deploy/scanworker.sh stop"
    if nuguard_on; then echo "NuGuard started beside it"; fi
    ;;
  run)
    # Foreground, for systemd: stops (and marks running requests
    # interrupted) when the unit stops.
    if [ -z "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then echo "VULNFRAMEWORK_GITHUB_TOKEN is not set" >&2; exit 1; fi
    export VULNFRAMEWORK_GITHUB_TOKEN
    need_nuguard_key
    exec "${compose[@]}" up --no-log-prefix "${services[@]}"
    ;;
  stop)
    # The sidecar first: it lives in the worker's network namespace.
    "${compose[@]}" stop nuguard scanworker
    "${compose[@]}" rm -f nuguard scanworker >/dev/null
    echo "scan worker stopped and removed; the token is no longer in any container"
    ;;
  status)
    "${compose[@]}" ps scanworker nuguard
    ;;
  *)
    echo "usage: deploy/scanworker.sh start|stop|status" >&2
    exit 2
    ;;
esac
