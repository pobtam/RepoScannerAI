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
# On the GCP VM, systemd runs this as vulnframework-scanworker.service with
# the token read from Secret Manager; stop it with
#   sudo systemctl stop vulnframework-scanworker
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
files=(-f "$ROOT/deploy/compose.yaml")
[ -n "${VF_COMPOSE_OVERRIDE:-}" ] && files+=(-f "$VF_COMPOSE_OVERRIDE")
compose=(docker compose --env-file "${VF_ENV_FILE:-$ROOT/deploy/.env}" "${files[@]}" --profile worker)

case "${1:-}" in
  start)
    if [ -z "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then
      echo "VULNFRAMEWORK_GITHUB_TOKEN is not set. Use a fine-grained token with only" >&2
      echo "Contents: read-only and Metadata: read-only." >&2
      exit 1
    fi
    export VULNFRAMEWORK_GITHUB_TOKEN
    "${compose[@]}" up -d scanworker
    echo "scan worker started; it holds the token until: deploy/scanworker.sh stop"
    ;;
  run)
    # Foreground, for systemd: stops (and marks running requests
    # interrupted) when the unit stops.
    if [ -z "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then echo "VULNFRAMEWORK_GITHUB_TOKEN is not set" >&2; exit 1; fi
    export VULNFRAMEWORK_GITHUB_TOKEN
    exec "${compose[@]}" up --no-log-prefix scanworker
    ;;
  stop)
    "${compose[@]}" stop scanworker
    "${compose[@]}" rm -f scanworker >/dev/null
    echo "scan worker stopped and removed; the token is no longer in any container"
    ;;
  status)
    "${compose[@]}" ps scanworker
    ;;
  *)
    echo "usage: deploy/scanworker.sh start|stop|status" >&2
    exit 2
    ;;
esac
