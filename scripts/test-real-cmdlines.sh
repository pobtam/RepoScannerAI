#!/usr/bin/env bash
# scripts/test-real-cmdlines.sh — the container command lines real mode runs,
# rendered without running anything, and compared with recorded ones.
#
#   scripts/test-real-cmdlines.sh            check
#   scripts/test-real-cmdlines.sh --update   rewrite the recorded NuGuard lines
#
# It runs real_worker_start and real_sweep from scripts/real.sh, the same
# functions run.sh --real calls, with docker and go replaced by recorders. So
# what it checks is the code path that runs, not a copy of it.
#
# scripts/testdata/real-cmdlines.golden holds the command lines of real mode
# WITHOUT --nuguard, recorded from real.sh before NuGuard existed in it. It is
# never rewritten by --update: real mode without --nuguard must not change.
#
# It also checks that the API server and the interface's dev server, started
# through scripts/launch.sh as run.sh starts them, get neither the NuGuard
# key nor a GitHub token.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOLDEN="$ROOT/scripts/testdata"
UPDATE=0
[ "${1:-}" = "--update" ] && UPDATE=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# render NAME [ENV=VALUE...] records the docker run lines real mode would
# use. The recorder writes to a file: real.sh sends docker's own output to
# /dev/null (the worker) or to the sweep record.
render() {
  local name="$1"; shift
  : >"$WORK/cmdlog"
  env -i HOME="$WORK/home" PATH="$PATH" CMDLOG="$WORK/cmdlog" "$@" bash -c '
    set -euo pipefail
    ROOT="$1"; CLONES="$2"
    docker() {
      case "$1" in
        image) echo arm64 ;; # image inspect --format {{.Architecture}}
        run) { printf "docker"; printf " %q" "$@"; printf "\n"; } >>"$CMDLOG" ;;
        *) : ;;              # rm -f, stop
      esac
    }
    go() { :; }
    # shellcheck source=real.sh
    . "$ROOT/scripts/real.sh"
    real_active_repos() { echo smoke/go-api; }
    REAL_BIN="$HOME/bin" # the sweep record lands here, not in the repository
    echo "## worker" >>"$CMDLOG"
    real_worker_start "$CLONES" >/dev/null 2>&1
    echo "## sweep" >>"$CMDLOG"
    real_sweep "$CLONES" >/dev/null 2>&1
  ' render "$ROOT" "$WORK/clones"
  sed -e "s#$ROOT#<ROOT>#g" -e "s#$WORK#<WORK>#g" "$WORK/cmdlog" >"$WORK/$name"
}

mkdir -p "$WORK/clones/go-api" "$WORK/home"

fail=0
check() {
  local name="$1"
  # The lines without --nuguard are recorded once, never updated.
  if [ "$UPDATE" -eq 1 ] && { [ "$name" != real-cmdlines.golden ] || [ ! -f "$GOLDEN/$name" ]; }; then
    cp "$WORK/$name" "$GOLDEN/$name"
    echo "updated $name"
    return
  fi
  if diff -u "$GOLDEN/$name" "$WORK/$name"; then
    echo "ok  $name"
  else
    echo "FAIL $name differs from the recorded lines" >&2
    fail=1
  fi
}

# Without --nuguard: exactly the recorded lines, whatever NuGuard variables
# happen to be set in the shell, since only run.sh --nuguard turns it on.
render real-cmdlines.golden
check real-cmdlines.golden
render without-flag VULNFRAMEWORK_NUGUARD_API_KEY=not-a-key NUGUARD_PORT=9999
cp "$WORK/without-flag" "$WORK/real-cmdlines.golden"
check real-cmdlines.golden

# With --nuguard (what run.sh exports for it).
render real-cmdlines-nuguard.golden REAL_NUGUARD=1 REAL_NUGUARD_PORT=8090 \
  VULNFRAMEWORK_NUGUARD_API_KEY=not-a-key
check real-cmdlines-nuguard.golden
if grep -q 'not-a-key' "$WORK/real-cmdlines-nuguard.golden"; then
  echo "FAIL the NuGuard API key's value is on a command line" >&2
  fail=1
fi

# The optional GitHub token for private repositories: by name, never value.
render with-token REAL_NUGUARD=1 VULNFRAMEWORK_NUGUARD_API_KEY=not-a-key VULNFRAMEWORK_GITHUB_TOKEN=not-a-token
if [ "$(grep -c -- '-e VULNFRAMEWORK_GITHUB_TOKEN ' "$WORK/with-token")" != 2 ] ||
  grep -qE 'not-a-(key|token)' "$WORK/with-token"; then
  echo "FAIL the GitHub token is not passed by name to both containers" >&2
  fail=1
else
  echo "ok  the GitHub token is passed by name only"
fi

# The API server and the interface's dev server start without either
# credential, even with both exported in run.sh's shell: only the scan
# containers need them. Recorders named go and npm, first on PATH, are what
# the launchers really execute, so this checks the environment they really
# get, not the text of a command.
mkdir -p "$WORK/fakebin"
for tool in go npm; do
  cat >"$WORK/fakebin/$tool" <<'REC'
#!/usr/bin/env bash
{
  printf '%s' "$(basename "$0")"; printf ' %q' "$@"; printf '\n'
  for v in VULNFRAMEWORK_NUGUARD_API_KEY VULNFRAMEWORK_GITHUB_TOKEN; do
    if [ -n "${!v+set}" ]; then printf 'LEAK %s\n' "$v"; fi
  done
} >>"$LAUNCHLOG"
REC
  chmod +x "$WORK/fakebin/$tool"
done
: >"$WORK/launch"
env -i HOME="$WORK/home" PATH="$WORK/fakebin:$PATH" LAUNCHLOG="$WORK/launch" \
  VULNFRAMEWORK_NUGUARD_API_KEY=not-a-key VULNFRAMEWORK_GITHUB_TOKEN=not-a-token bash -c '
    set -euo pipefail
    . "$1/scripts/launch.sh"
    (launch_api -addr 127.0.0.1:18080 -dsn postgres://example.invalid/db)
    (launch_ui exec 15173 18080)
    (launch_ui wait 15173 18080)
  ' launch "$ROOT"
api="$(grep -c '^go run ./cmd/apiserver -addr 127.0.0.1:18080 ' "$WORK/launch" || true)"
ui="$(grep -c '^npm run dev -- --host 127.0.0.1 --port 15173 --strictPort$' "$WORK/launch" || true)"
if [ "$api" != 1 ] || [ "$ui" != 2 ]; then
  echo "FAIL the launchers did not run the API server once and the dev server twice:" >&2
  cat "$WORK/launch" >&2
  fail=1
elif grep -q '^LEAK\|not-a-' "$WORK/launch"; then
  echo "FAIL a credential reached the API server or the dev server:" >&2
  grep '^LEAK' "$WORK/launch" >&2
  fail=1
else
  echo "ok  the API and dev servers start without the NuGuard key or a GitHub token"
fi

[ "$fail" -eq 0 ] && echo "COMMAND LINES OK"
exit "$fail"
