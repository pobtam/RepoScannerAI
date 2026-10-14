#!/usr/bin/env bash
# deploy/vfctl.sh — run vfctl against the deployed stack's database.
#
#   sudo deploy/vfctl.sh github status
#   sudo deploy/vfctl.sh repo exclude owner/name -reason "a vendored mirror"
#   sudo deploy/vfctl.sh finding pending
#
# vfctl runs in the API image on the compose network, so the database is
# never published. Commands that talk to GitHub (github connect|discover)
# need VULNFRAMEWORK_GITHUB_TOKEN in the environment; on the GCP VM:
#   sudo VULNFRAMEWORK_GITHUB_TOKEN="$(/usr/local/bin/vf-secret vulnframework-github-token)" deploy/vfctl.sh github discover
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${VF_ENV_FILE:-$ROOT/deploy/.env}"
# VF_COMPOSE_OVERRIDE names an extra compose file layered on top (the stack
# test uses one); unset, only deploy/compose.yaml is used.
files=(-f "$ROOT/deploy/compose.yaml")
[ -n "${VF_COMPOSE_OVERRIDE:-}" ] && files+=(-f "$VF_COMPOSE_OVERRIDE")

# shellcheck disable=SC1090
POSTGRES_PASSWORD="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$ENV_FILE")"
[ -n "$POSTGRES_PASSWORD" ] || { echo "no POSTGRES_PASSWORD in $ENV_FILE" >&2; exit 1; }
exec docker compose --env-file "$ENV_FILE" "${files[@]}" run --rm -T --no-deps \
  -e VULNFRAMEWORK_GITHUB_TOKEN \
  --entrypoint /usr/local/bin/vfctl migrate \
  -dsn "postgres://vulnframework:${POSTGRES_PASSWORD}@db:5432/vulnframework?sslmode=disable" "$@"
