#!/usr/bin/env bash
# deploy/sweep.sh — run one sweep: discover what the token reaches, then
# download, scan and record each repository. Read-only towards GitHub.
#
# The token is taken from $VULNFRAMEWORK_GITHUB_TOKEN for this run only and
# handed to the sweep container by name, so it never appears on a command
# line or in a file. On the GCP VM, the systemd timer fetches it from Secret
# Manager just before calling this.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -z "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then
  echo "VULNFRAMEWORK_GITHUB_TOKEN is not set. Use a fine-grained token with only" >&2
  echo "Contents: read-only and Metadata: read-only." >&2
  exit 1
fi
export VULNFRAMEWORK_GITHUB_TOKEN

# Settings come from deploy/.env, or from the file VF_ENV_FILE names.
# Arguments are NOT passed through: `compose run` would replace the sweep's
# whole command with them.
env_file=(--env-file "${VF_ENV_FILE:-$ROOT/deploy/.env}")

# VF_COMPOSE_OVERRIDE names an extra compose file layered on top (the stack
# test uses one); unset, only deploy/compose.yaml is used.
files=(-f "$ROOT/deploy/compose.yaml")
[ -n "${VF_COMPOSE_OVERRIDE:-}" ] && files+=(-f "$VF_COMPOSE_OVERRIDE")

mkdir -p "$ROOT/deploy/runs"
out="$ROOT/deploy/runs/sweep-$(date -u +%Y%m%dT%H%M%SZ).json"
docker compose "${env_file[@]}" "${files[@]}" --profile jobs run --rm -T sweep >"$out"
echo "sweep complete; the run record is in $out"
