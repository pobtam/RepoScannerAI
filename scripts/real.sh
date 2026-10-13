# scripts/real.sh — helpers for running the framework against REAL repositories.
#
# Sourced by run.sh --real and vfctl.sh; not run directly. Everything here is
# read-only towards your repositories and towards GitHub:
#
#   * clones are mounted into the scan container READ-ONLY;
#   * no GitHub credential exists anywhere in this path, and nothing opens a
#     pull request, comments, or creates a ticket — the orchestrator's
#     post-sweep pass stops at the routing decision;
#   * the scanner image is checked against config/tools.lock and NOT rebuilt
#     if it differs.
#
# The database is the same Docker container and volume run.sh --postgres uses
# (vulnframework-pg, volume vulnframework-pgdata); VULNFRAMEWORK_PG_CONTAINER,
# VULNFRAMEWORK_PG_VOLUME and VULNFRAMEWORK_PG_PORT override them.

REAL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REAL_VF="$REAL_ROOT/vulnframework"
REAL_BIN="$REAL_VF/bin"

REAL_PG_PORT="${VULNFRAMEWORK_PG_PORT:-5433}"
REAL_PG_NAME="${VULNFRAMEWORK_PG_CONTAINER:-vulnframework-pg}"
REAL_PG_VOLUME="${VULNFRAMEWORK_PG_VOLUME:-vulnframework-pgdata}"
REAL_DSN="${VULNFRAMEWORK_DSN:-postgres://vulnframework:vulnframework@localhost:${REAL_PG_PORT}/vulnframework?sslmode=disable}"
# The same database as seen from inside the scan container.
REAL_DSN_CONTAINER="${REAL_DSN//localhost/host.docker.internal}"
REAL_DSN_CONTAINER="${REAL_DSN_CONTAINER//127.0.0.1/host.docker.internal}"

REAL_SCANNER_IMAGE="$(awk '$1=="image"{print $2; exit}' "$REAL_VF/config/tools.lock")"

# The public exploitation feeds. Downloading them sends nothing about your
# code: each is one GET of the whole catalogue.
REAL_KEV_URL="${VULNFRAMEWORK_KEV_URL:-https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}"
REAL_EPSS_URL="${VULNFRAMEWORK_EPSS_URL:-https://epss.empiricalsecurity.com/epss_scores-current.csv.gz}"

# Your organisation's first-party module registry, if you have written one.
REAL_FIRSTPARTY="$REAL_VF/config/firstparty.yaml"

real_red=$'\033[0;31m'
real_bold=$'\033[1m'
real_green=$'\033[0;32m'
real_plain=$'\033[0m'

real_fail() {
  printf '%s%s%s\n' "$real_red" "$*" "$real_plain" >&2
  return 1
}

real_need_docker() {
  command -v docker >/dev/null 2>&1 || real_fail "Docker is required for real mode. Install Docker Desktop and start it." || return 1
  docker info >/dev/null 2>&1 || real_fail "Docker is installed but not running. Start Docker Desktop and try again." || return 1
}

# real_pg_up starts the database container if it is not already running and
# waits for it. Prints 1 if this call started it, 0 if it was already up.
real_pg_up() {
  if docker ps --format '{{.Names}}' | grep -qx "$REAL_PG_NAME"; then
    echo 0
    return 0
  fi
  docker run -d --rm --name "$REAL_PG_NAME" \
    -e POSTGRES_USER=vulnframework \
    -e POSTGRES_PASSWORD=vulnframework \
    -e POSTGRES_DB=vulnframework \
    -p "127.0.0.1:${REAL_PG_PORT}:5432" \
    -v "$REAL_PG_VOLUME:/var/lib/postgresql/data" \
    postgres:16-alpine >/dev/null
  for _ in $(seq 1 60); do
    if docker exec "$REAL_PG_NAME" pg_isready -U vulnframework >/dev/null 2>&1; then
      echo 1
      return 0
    fi
    sleep 1
  done
  real_fail "The database did not become ready."
}

real_migrate() {
  (cd "$REAL_VF" && go run ./cmd/orchestrator -dsn "$REAL_DSN" -migrate 2>&1 | tail -n 1) >/dev/null ||
    real_fail "Migrating the database failed. Run: (cd vulnframework && go run ./cmd/orchestrator -dsn \"$REAL_DSN\" -migrate)"
}

real_vfctl() {
  (cd "$REAL_VF" && go run ./cmd/vfctl -dsn "$REAL_DSN" "$@")
}

# real_active_repos prints the names of registered, non-archived repositories.
real_active_repos() {
  real_vfctl repo list | awk 'NR>1 && $NF=="active"{print $1}'
}

real_verify_image() {
  printf '%sChecking the scanner image %s against config/tools.lock…%s\n' "$real_bold" "$REAL_SCANNER_IMAGE" "$real_plain"
  "$REAL_VF/deploy/scanner/verify-image.sh" "$REAL_SCANNER_IMAGE" "$REAL_VF/config/tools.lock"
}

# real_sweep CLONES scans every registered repository from CLONES/<name>,
# inside the scanner image, and runs the post-sweep pass.
real_sweep() {
  local clones="$1"
  local missing=0 repo
  while read -r repo; do
    [ -n "$repo" ] || continue
    if [ ! -d "$clones/${repo##*/}" ]; then
      printf '  %s is registered but %s does not exist\n' "$repo" "$clones/${repo##*/}" >&2
      missing=1
    fi
  done < <(real_active_repos)
  if [ "$missing" -ne 0 ]; then
    real_fail "Clone the missing repositories into $clones (the folder name must be the last part of the registered name), or archive them with ./vfctl.sh repo remove NAME." || return 1
  fi

  local arch
  arch="$(docker image inspect "$REAL_SCANNER_IMAGE" --format '{{.Architecture}}')"
  mkdir -p "$REAL_BIN/real-runs"
  (cd "$REAL_VF" && GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -o "$REAL_BIN/orchestrator-linux-$arch" ./cmd/orchestrator) ||
    real_fail "Building the orchestrator for the scan container failed." || return 1

  local args=(
    -dsn "$REAL_DSN_CONTAINER"
    -workdir /repos
    -tools /opt/vf/config/tools.lock
    -calibration /opt/vf/config/calibration.yaml
    -policy /opt/vf/config/policy.yaml
    -kev-url "$REAL_KEV_URL"
    -epss-url "$REAL_EPSS_URL"
  )
  local env=(
    # Semgrep otherwise reports usage metrics and checks for a newer version.
    -e SEMGREP_SEND_METRICS=off
    -e SEMGREP_ENABLE_VERSION_CHECK=0
  )
  if [ -f "$REAL_FIRSTPARTY" ]; then
    args+=(-firstparty /opt/vf/config/firstparty.yaml)
  fi
  # AI triage only when BOTH are set. -e NAME with no value passes the key
  # from this shell without it appearing on a command line.
  if [ -n "${VULNFRAMEWORK_TRIAGE_MODEL:-}" ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    args+=(-triage-model "$VULNFRAMEWORK_TRIAGE_MODEL")
    env+=(-e ANTHROPIC_API_KEY)
    printf '%sAI triage is ON (%s): finding details will be sent to the Anthropic API.%s\n' "$real_bold" "$VULNFRAMEWORK_TRIAGE_MODEL" "$real_plain"
  fi

  local out
  out="$REAL_BIN/real-runs/sweep-$(date +%Y%m%d-%H%M%S).json"
  printf '%sSweeping (this can take several minutes per repository)…%s\n' "$real_bold" "$real_plain"
  if ! docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$clones:/repos:ro" \
    -v "$REAL_BIN/orchestrator-linux-$arch:/opt/vf/orchestrator:ro" \
    -v "$REAL_VF/config:/opt/vf/config:ro" \
    -v vulnframework-scanhome:/home/scanner \
    "${env[@]}" \
    --entrypoint /opt/vf/orchestrator \
    "$REAL_SCANNER_IMAGE" "${args[@]}" >"$out"; then
    real_fail "The sweep failed; its output so far is in $out." || return 1
  fi
  printf '%s  ✓ sweep complete; the full record is in %s%s\n' "$real_green" "${out#"$REAL_ROOT"/}" "$real_plain"
}
