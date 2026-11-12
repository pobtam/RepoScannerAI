# scripts/real.sh — helpers for running the framework against REAL repositories.
#
# Sourced by run.sh --real and vfctl.sh; not run directly. Everything here is
# read-only towards your repositories and towards GitHub:
#
#   * clones are mounted into the scan container READ-ONLY;
#   * no GitHub credential exists anywhere in this path, and nothing opens a
#     pull request, comments, or creates a ticket — the orchestrator's
#     post-sweep pass stops at the routing decision. The one exception is
#     opt-in: with --nuguard, a read-only token in VULNFRAMEWORK_GITHUB_TOKEN,
#     if you set one, is passed on so NuGuard can clone private repositories;
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

# NuGuard on this Mac (run.sh --real --nuguard, scripts/nuguard-local.sh).
# Off unless run.sh sets REAL_NUGUARD=1; the API key is read from
# VULNFRAMEWORK_NUGUARD_API_KEY and passed into the container by name only.
REAL_NUGUARD="${REAL_NUGUARD:-0}"
REAL_NUGUARD_PORT="${REAL_NUGUARD_PORT:-8090}"

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
  # Over TCP: on first start the image runs a temporary server on its socket
  # only, which answers pg_isready and then restarts under the migration.
  for _ in $(seq 1 60); do
    if docker exec "$REAL_PG_NAME" pg_isready -h 127.0.0.1 -U vulnframework >/dev/null 2>&1; then
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

# real_backup_if_migrating backs the database up (scripts/db.sh backup)
# before a binary with newer migrations changes it, and says where the
# backup is. A new, empty database has nothing to keep.
real_backup_if_migrating() {
  local have want
  want="$(cd "$REAL_VF/internal/store/migrations" && ls ./*.up.sql | sed -n 's#^\./0*\([0-9][0-9]*\)_.*#\1#p' | sort -n | tail -n 1)"
  have="$(docker exec "$REAL_PG_NAME" psql -X -q -tA -U vulnframework -d vulnframework \
    -c 'SELECT max(version) FROM schema_migrations' 2>/dev/null | tr -d '[:space:]' || true)"
  case "$have" in '' | *[!0-9]*) return 0 ;; esac
  [ "$have" -lt "$want" ] || return 0
  printf '%sThe database is at schema %s and this version migrates it to %s; backing it up first…%s\n' \
    "$real_bold" "$have" "$want" "$real_plain"
  "$REAL_ROOT/scripts/db.sh" backup --target real ||
    real_fail "The backup failed, so the database was not migrated. Nothing has changed; fix the backup (scripts/db.sh backup) and try again."
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

# real_prepare_container builds the orchestrator for the scanner image and
# fills REAL_ARCH, REAL_ARGS and REAL_ENV, shared by the one-shot sweep and
# the scan worker so both scan with the same image, mounts and flags.
real_prepare_container() {
  REAL_ARCH="$(docker image inspect "$REAL_SCANNER_IMAGE" --format '{{.Architecture}}')"
  mkdir -p "$REAL_BIN/real-runs"
  (cd "$REAL_VF" && GOOS=linux GOARCH="$REAL_ARCH" CGO_ENABLED=0 go build -o "$REAL_BIN/orchestrator-linux-$REAL_ARCH" ./cmd/orchestrator) ||
    real_fail "Building the orchestrator for the scan container failed." || return 1

  REAL_ARGS=(
    -dsn "$REAL_DSN_CONTAINER"
    -workdir /repos
    -tools /opt/vf/config/tools.lock
    -calibration /opt/vf/config/calibration.yaml
    -policy /opt/vf/config/policy.yaml
    -kev-url "$REAL_KEV_URL"
    -epss-url "$REAL_EPSS_URL"
  )
  REAL_ENV=(
    # Semgrep otherwise reports usage metrics and checks for a newer version.
    -e SEMGREP_SEND_METRICS=off
    -e SEMGREP_ENABLE_VERSION_CHECK=0
  )
  if [ -f "$REAL_FIRSTPARTY" ]; then
    REAL_ARGS+=(-firstparty /opt/vf/config/firstparty.yaml)
  fi
  # AI triage only when BOTH are set. -e NAME with no value passes the key
  # from this shell without it appearing on a command line.
  if [ -n "${VULNFRAMEWORK_TRIAGE_MODEL:-}" ] && [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    REAL_ARGS+=(-triage-model "$VULNFRAMEWORK_TRIAGE_MODEL")
    REAL_ENV+=(-e ANTHROPIC_API_KEY)
    printf '%sAI triage is ON (%s): finding details will be sent to the Anthropic API.%s\n' "$real_bold" "$VULNFRAMEWORK_TRIAGE_MODEL" "$real_plain"
  fi
  # What the container runs: the orchestrator, or with NuGuard the loopback
  # bridge first and then the orchestrator.
  REAL_ENTRY=(--entrypoint /opt/vf/orchestrator "$REAL_SCANNER_IMAGE")
  if [ "$REAL_NUGUARD" = 1 ]; then
    real_nuguard_container || return 1
  fi
}

# real_nuguard_container adds NuGuard to the container real_prepare_container
# describes. NuGuard listens on the Mac's 127.0.0.1 only. Inside the
# container the Mac is host.docker.internal, which the NuGuard client refuses
# plain http to (the API key crosses the connection), so a small bridge,
# cmd/loopbridge, listens on the container's own 127.0.0.1 and carries the
# bytes to the Mac over Docker Desktop's host connection. The client's
# loopback rule is unchanged.
real_nuguard_container() {
  [ -n "${VULNFRAMEWORK_NUGUARD_API_KEY:-}" ] ||
    real_fail "NuGuard is on but VULNFRAMEWORK_NUGUARD_API_KEY is not set: eval \"\$(scripts/nuguard-local.sh key)\"" || return 1
  (cd "$REAL_VF" && GOOS=linux GOARCH="$REAL_ARCH" CGO_ENABLED=0 go build -o "$REAL_BIN/loopbridge-linux-$REAL_ARCH" ./cmd/loopbridge) ||
    real_fail "Building the NuGuard bridge for the scan container failed." || return 1
  local port="$REAL_NUGUARD_PORT"
  # The ceiling (-nuguard-allow-*, -nuguard-max-timeout) and the defaults,
  # from the environment with deploy/compose.yaml's defaults, so the
  # interface's NuGuard controls work in real mode within the same ceiling.
  REAL_ARGS+=(
    -nuguard-url "http://127.0.0.1:$port"
    -nuguard-tools "${NUGUARD_TOOLS:-}"
    "-nuguard-include-posture=${NUGUARD_INCLUDE_POSTURE:-false}"
    -nuguard-timeout "${NUGUARD_TIMEOUT:-10m}"
    -nuguard-allow-tools "${NUGUARD_ALLOW_TOOLS:-nga-rules,atlas,semgrep}"
    "-nuguard-allow-posture=${NUGUARD_ALLOW_POSTURE:-true}"
    -nuguard-max-timeout "${NUGUARD_MAX_TIMEOUT:-10m}"
    -nuguard-sbom-max-bytes "${NUGUARD_SBOM_MAX_BYTES:-4194304}"
  )
  # By name only: the values never reach a command line.
  REAL_ENV+=(-e VULNFRAMEWORK_NUGUARD_API_KEY)
  if [ -n "${VULNFRAMEWORK_GITHUB_TOKEN:-}" ]; then
    REAL_ENV+=(-e VULNFRAMEWORK_GITHUB_TOKEN)
  fi
  local start
  start="/opt/vf/loopbridge -listen 127.0.0.1:$port -to host.docker.internal:$port -ready /tmp/loopbridge.ready &
i=0; while [ ! -e /tmp/loopbridge.ready ] && [ \$i -lt 100 ]; do sleep 0.1; i=\$((i + 1)); done
exec /opt/vf/orchestrator \"\$@\""
  REAL_ENTRY=(
    -v "$REAL_BIN/loopbridge-linux-$REAL_ARCH:/opt/vf/loopbridge:ro"
    --entrypoint /bin/sh "$REAL_SCANNER_IMAGE" -c "$start" orchestrator
  )
}

# real_nuguard_up starts NuGuard on this Mac unless it is already running
# and healthy, loads its API key into this shell, prints what will happen,
# and turns NuGuard on for the containers real_prepare_container describes.
# NUGUARD_STARTED is 1 when this call started it, so run.sh stops only a
# NuGuard it started.
real_nuguard_up() {
  local ng="$REAL_ROOT/scripts/nuguard-local.sh" state
  REAL_NUGUARD_PORT="${NUGUARD_PORT:-8090}"
  if curl -sf -m 3 "http://127.0.0.1:$REAL_NUGUARD_PORT/v1/readyz" >/dev/null 2>&1; then
    NUGUARD_STARTED=0
  else
    "$ng" start || return 1
    NUGUARD_STARTED=1
  fi
  eval "$("$ng" key)" || return 1
  [ -n "${VULNFRAMEWORK_NUGUARD_API_KEY:-}" ] || real_fail "Could not load NuGuard's API key." || return 1
  export VULNFRAMEWORK_NUGUARD_API_KEY
  state="$("$ng" status)" || return 1
  printf '%s\n' "$state"
  local version tree
  version="$(printf '%s\n' "$state" | sed -n 's/^  version *\([^ ]*\).*/\1/p')"
  tree="$(printf '%s\n' "$state" | sed -n 's/^  source .*, tree \(.*\)$/\1/p')"
  printf '%sNuGuard on%s (local, http://127.0.0.1:%s, version %s, tree %s); repositories without a GitHub origin will show NuGuard as not requested.\n' \
    "$real_bold" "$real_plain" "$REAL_NUGUARD_PORT" "$version" "$tree"
  REAL_NUGUARD=1
}

# real_worker_start CLONES starts the scan worker in the background: it runs
# the scans requested from the interface ("Scan now") and with
# ./vfctl.sh scan, from the clones, read-only. No GitHub token is involved in
# this mode. Stopped by real_worker_stop, which marks any scan it was running
# as interrupted.
REAL_WORKER_NAME="${VULNFRAMEWORK_WORKER_CONTAINER:-vulnframework-scanworker}"
real_worker_start() {
  local clones="$1"
  real_prepare_container || return 1
  docker rm -f "$REAL_WORKER_NAME" >/dev/null 2>&1 || true
  docker run -d --rm --name "$REAL_WORKER_NAME" \
    --add-host=host.docker.internal:host-gateway \
    -v "$clones:/repos:ro" \
    -v "$REAL_BIN/orchestrator-linux-$REAL_ARCH:/opt/vf/orchestrator:ro" \
    -v "$REAL_VF/config:/opt/vf/config:ro" \
    -v vulnframework-scanhome:/home/scanner \
    "${REAL_ENV[@]}" \
    "${REAL_ENTRY[@]}" "${REAL_ARGS[@]}" -worker -scan-timeout "${VULNFRAMEWORK_SCAN_TIMEOUT:-15m}" >/dev/null ||
    real_fail "Starting the scan worker failed." || return 1
  printf '%s  ✓ scan worker running (container %s); Scan now works in the interface%s\n' "$real_green" "$REAL_WORKER_NAME" "$real_plain"
}

real_worker_stop() {
  docker stop "$REAL_WORKER_NAME" >/dev/null 2>&1 || true
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

  real_prepare_container || return 1

  local out
  out="$REAL_BIN/real-runs/sweep-$(date +%Y%m%d-%H%M%S).json"
  printf '%sSweeping (this can take several minutes per repository)…%s\n' "$real_bold" "$real_plain"
  if ! docker run --rm \
    --add-host=host.docker.internal:host-gateway \
    -v "$clones:/repos:ro" \
    -v "$REAL_BIN/orchestrator-linux-$REAL_ARCH:/opt/vf/orchestrator:ro" \
    -v "$REAL_VF/config:/opt/vf/config:ro" \
    -v vulnframework-scanhome:/home/scanner \
    "${REAL_ENV[@]}" \
    "${REAL_ENTRY[@]}" "${REAL_ARGS[@]}" >"$out"; then
    real_fail "The sweep failed; its output so far is in $out." || return 1
  fi
  printf '%s  ✓ sweep complete; the full record is in %s%s\n' "$real_green" "${out#"$REAL_ROOT"/}" "$real_plain"
}
