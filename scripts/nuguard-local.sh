#!/usr/bin/env bash
#
# scripts/nuguard-local.sh — run NuGuard on this Mac for real mode.
#
#   scripts/nuguard-local.sh start    set up NuGuard's environment if needed,
#                                     then start the service in the background
#   scripts/nuguard-local.sh stop     stop the service this script started
#   scripts/nuguard-local.sh status   what is running, which NuGuard, and
#                                     whether its source has uncommitted work
#   eval "$(scripts/nuguard-local.sh key)"
#                                     put the API key in this shell's
#                                     VULNFRAMEWORK_NUGUARD_API_KEY
#
# ./run.sh --real --nuguard calls start, key and stop for you.
#
# NuGuard comes from the checkout in NUGUARD_DIR (default ../nuguard next to
# this repository). It listens on 127.0.0.1 only, port NUGUARD_PORT (default
# 8090), with an API key created on first start. Everything it keeps is in
# ~/.local/share/vulnframework/nuguard (VF_NUGUARD_HOME overrides), readable
# only by you: the key, the service's settings (which hold the key's SHA-256,
# never the key), its own Python environment, Semgrep's, its database and its
# log. Delete that folder to start again from nothing.
#
# Reproducible results:
#   * with uv, NuGuard's environment is built from the checkout's lockfile
#     (uv sync --frozen); without uv, with pip, and status then says
#     "dependencies not from lockfile". It is rebuilt when pyproject.toml,
#     uv.lock, the Semgrep pin or the install method changes.
#   * Semgrep, at NuGuard's CI pin, has an environment of its own, as in
#     NuGuard's image: in NuGuard's it breaks on a dependency conflict.
#   * Every result records the source in provenance.image_digest, which
#     vulnframework keeps as nuguard/image: git:<commit>, plus -dirty when
#     the checkout had uncommitted changes at start. For this native run it
#     is a git commit, not an image digest.
#   * tools.json in the folder above gives the service the versions of the
#     Semgrep, NuGuard and git it runs with (NUGUARD_TOOLS_JSON).
#
# What leaves this Mac: NuGuard clones each repository it is asked to scan
# from github.com. It needs Python 3.12 or newer, and uv if you have it.

set -euo pipefail
{ set +x; } 2>/dev/null # never trace: the key passes through this script

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${VF_NUGUARD_HOME:-$HOME/.local/share/vulnframework/nuguard}"
PORT="${NUGUARD_PORT:-8090}"
VENV="$STATE/venv"
SEMGREP_VENV="$STATE/semgrep"
TOOLS_JSON="$STATE/tools.json"
SOURCE_FILE="$STATE/source" # what the running service was started from
CONFIG="$STATE/nuguard.yaml"
KEYFILE="$STATE/api-key"
KEYHASH="$STATE/api-key.sha256"
PIDFILE="$STATE/nuguard.pid"
LOG="$STATE/nuguard.log"
URL="http://127.0.0.1:$PORT"
KEY_ID=real-mode

BOLD=$'\033[1m'
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
PLAIN=$'\033[0m'

die() { printf '%s%s%s\n' "$RED" "$*" "$PLAIN" >&2; exit 1; }
say() { printf '%s\n' "$*" >&2; }

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "${BASH_SOURCE[0]}"
}

# The version config/tools.lock pins: the service must report exactly it.
PINNED="$(awk '$1=="tool" && $2=="nuguard"{print $3; exit}' "$ROOT/vulnframework/config/tools.lock")"

# nuguard_dir finds the NuGuard checkout. A checkout one level down
# (../nuguard/nuguard, as a folder holding the clone) is accepted too.
nuguard_dir() {
  local d="${NUGUARD_DIR:-$ROOT/../nuguard}"
  if [ -z "${NUGUARD_DIR:-}" ] && [ ! -f "$d/pyproject.toml" ] && [ -f "$d/nuguard/pyproject.toml" ]; then
    d="$d/nuguard"
  fi
  [ -d "$d" ] || die "No NuGuard checkout at $d. Clone it there, or set NUGUARD_DIR."
  d="$(cd "$d" && pwd)"
  [ -f "$d/pyproject.toml" ] || die "$d has no pyproject.toml: it is not a NuGuard checkout (set NUGUARD_DIR)."
  [ -d "$d/nuguard/service" ] || die "$d has no nuguard/service: this NuGuard has no remote scan service."
  printf '%s\n' "$d"
}

# semgrep_pin is the Semgrep version NuGuard is tested with: its CI's pin,
# else its service image's.
semgrep_pin() {
  local d="$1" v
  v="$(grep -rhoE 'semgrep==[0-9][0-9.]*' "$d/.github/workflows" 2>/dev/null | head -n 1 | cut -d= -f3)"
  [ -n "$v" ] || v="$(sed -n 's/^ARG SEMGREP_VERSION=//p' "$d/deploy/service/Dockerfile" 2>/dev/null | head -n 1)"
  [ -n "$v" ] || die "Could not find NuGuard's Semgrep version in $d/.github/workflows or deploy/service/Dockerfile."
  printf '%s\n' "$v"
}

# python312 finds a Python 3.12 or newer, preferring 3.12, which NuGuard is
# tested with.
python312() {
  local p
  for p in "${NUGUARD_PYTHON:-}" python3.12 "$HOME"/.local/share/uv/python/cpython-3.12*/bin/python3.12 \
    python3.13 python3.14 python3; do
    [ -n "$p" ] || continue
    command -v "$p" >/dev/null 2>&1 || [ -x "$p" ] || continue
    if "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' 2>/dev/null; then
      command -v "$p" 2>/dev/null || printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

# deps_mode says how ensure_env installs NuGuard: from its lockfile with uv,
# or with pip when uv (or the lockfile) is missing.
deps_mode() {
  if command -v uv >/dev/null 2>&1 && [ -f "$1/uv.lock" ]; then echo lockfile; else echo pip; fi
}

# ensure_env creates or updates NuGuard's own Python environment, separate
# from the checkout's .venv, and Semgrep's, separate from both and from any
# Semgrep on this Mac. They are rebuilt from nothing when NuGuard's
# dependencies, the Semgrep pin or the install method change.
ensure_env() {
  local d="$1" pin mode stamp
  pin="$(semgrep_pin "$d")"
  mode="$(deps_mode "$d")"
  stamp="$(cat "$d/pyproject.toml" "$d/uv.lock" 2>/dev/null | shasum -a 256 | cut -c1-16)-$mode-semgrep-$pin"
  if [ -x "$VENV/bin/nuguard" ] && [ -x "$SEMGREP_VENV/bin/semgrep" ] &&
    [ "$(cat "$VENV/.vf-stamp" 2>/dev/null)" = "$stamp" ]; then
    return 0
  fi
  say "${BOLD}Setting up NuGuard's environment in $VENV (a few minutes)…${PLAIN}"
  mkdir -p "$STATE"
  chmod 700 "$STATE"
  # From nothing: uv must not adopt what pip installed, nor the reverse, and
  # no Semgrep may stay in NuGuard's environment from an older version of
  # this script.
  rm -rf "${VENV:?}" "${SEMGREP_VENV:?}"
  if [ "$mode" = lockfile ]; then
    # --frozen: install exactly NuGuard's lockfile, and never rewrite it in
    # the checkout.
    (cd "$d" && UV_PROJECT_ENVIRONMENT="$VENV" uv sync --frozen --no-dev --extra service --extra secrets --python 3.12 >&2) ||
      die "uv sync failed; see above."
    uv venv --quiet --python 3.12 "$SEMGREP_VENV" >&2 &&
      uv pip install --quiet --python "$SEMGREP_VENV/bin/python" "semgrep==$pin" >&2 ||
      die "Installing semgrep==$pin into $SEMGREP_VENV failed; see above."
  else
    local py
    py="$(python312)" || die "NuGuard needs Python 3.12 or newer, and none was found. Install one with Homebrew:
  brew install python@3.12      (or: brew install uv)
then run this again."
    "$py" -m venv "$VENV" || die "Creating $VENV failed."
    "$VENV/bin/python" -m pip install --quiet --upgrade pip >&2
    "$VENV/bin/python" -m pip install --quiet -e "$d[service,secrets]" >&2 ||
      die "Installing NuGuard into $VENV failed; see above."
    "$py" -m venv "$SEMGREP_VENV" && "$SEMGREP_VENV/bin/python" -m pip install --quiet "semgrep==$pin" >&2 ||
      die "Installing semgrep==$pin into $SEMGREP_VENV failed; see above."
  fi
  # macOS can mark the editable install's .pth file hidden, and Python then
  # skips it: nuguard would not import. Clear the flag.
  find "$VENV" -name '*.pth' -exec chflags nohidden {} + 2>/dev/null || true
  "$VENV/bin/python" -c 'import nuguard.service' 2>/dev/null ||
    die "NuGuard does not import in $VENV. Delete $VENV and run this again."
  semgrep_version >/dev/null || die "Semgrep does not run from $SEMGREP_VENV. Delete it and run this again."
  printf '%s\n' "$mode" >"$VENV/.vf-deps"
  printf '%s\n' "$stamp" >"$VENV/.vf-stamp"
}

# semgrep_version prints the version of NuGuard's Semgrep.
semgrep_version() {
  SEMGREP_ENABLE_VERSION_CHECK=0 "$SEMGREP_VENV/bin/semgrep" --version 2>/dev/null |
    grep -Eo '^[0-9]+\.[0-9]+(\.[0-9]+)?$' | tail -n 1 | grep .
}

# write_tools_json records the versions the service runs with, in the format
# of /etc/nuguard/tools.json in NuGuard's image (a JSON object of tool name
# to version), for provenance.tools and /v1/capabilities.
write_tools_json() {
  local ng sg gt
  ng="$("$VENV/bin/python" -c 'from importlib.metadata import version; print(version("nuguard"))')" ||
    die "Could not read NuGuard's version from $VENV."
  sg="$(semgrep_version)" || die "Could not read Semgrep's version from $SEMGREP_VENV."
  gt="$(git --version | grep -Eo '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1)"
  ( umask 077
    "$VENV/bin/python" -c 'import json, sys
names = ("nuguard", "semgrep", "git")
tools = {n: v for n, v in zip(names, sys.argv[1:]) if v}
with open(sys.argv[-1], "w") as f:
    json.dump(tools, f, indent=2, sort_keys=True)
    f.write("\n")' "$ng" "$sg" "$gt" "$TOOLS_JSON.tmp" && mv "$TOOLS_JSON.tmp" "$TOOLS_JSON" ) ||
    die "Writing $TOOLS_JSON failed."
}

# ensure_key creates the API key once. The key is written only to KEYFILE,
# mode 0600; the service settings get its SHA-256.
ensure_key() {
  [ -s "$KEYFILE" ] && [ -s "$KEYHASH" ] && return 0
  local out key hash
  out="$(cd "$STATE" && "$VENV/bin/nuguard" serve keygen --id "$KEY_ID")" || die "nuguard serve keygen failed."
  key="$(printf '%s\n' "$out" | sed -n 's/^API key (shown once[^:]*): *//p')"
  hash="$(printf '%s\n' "$out" | sed -n 's/^ *sha256: *//p')"
  [ -n "$key" ] && [ "${#hash}" -eq 64 ] || die "nuguard serve keygen printed something unexpected; no key was saved."
  ( umask 077
    printf '%s' "$key" >"$KEYFILE.tmp" && mv "$KEYFILE.tmp" "$KEYFILE"
    printf '%s\n' "$hash" >"$KEYHASH" )
  chmod 600 "$KEYFILE" "$KEYHASH"
  say "Created NuGuard's API key in $KEYFILE (not shown)."
}

# write_config writes the service settings. Rewritten on every start, so the
# proxy and certificate variables match this shell.
write_config() {
  local passthrough="" v
  for v in HTTPS_PROXY HTTP_PROXY NO_PROXY ALL_PROXY https_proxy http_proxy no_proxy all_proxy \
    SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE GIT_SSL_CAINFO CURL_CA_BUNDLE; do
    if [ -n "${!v:-}" ]; then passthrough="$passthrough${passthrough:+, }$v"; fi
  done
  mkdir -p "$STATE/scratch"
  ( umask 077
    cat >"$CONFIG.tmp" <<EOF
# Written by scripts/nuguard-local.sh on every start; edits are overwritten.
service:
  bind: 127.0.0.1
  port: \${NUGUARD_PORT:-8090}
  api_keys:
    - id: $KEY_ID
      sha256: $(cat "$KEYHASH")
  git:
    allowed_hosts: [github.com]
  jobs:
    max_concurrent: 2
    scratch_dir: $STATE/scratch
    db_path: $STATE/service.db
    passthrough_env: [$passthrough]
  analysis_defaults:
    tools: [nga-rules, atlas, semgrep]
  llm:
    enabled: false
EOF
    mv "$CONFIG.tmp" "$CONFIG" )
  chmod 600 "$CONFIG"
}

# our_pid prints the pid of the service this script started, if it is still
# that process.
our_pid() {
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
  case "$(ps -p "$pid" -o command= 2>/dev/null)" in
    *nuguard*serve*) printf '%s\n' "$pid" ;;
    *) return 1 ;; # the pid was reused by something else
  esac
}

ready() { curl -sf -m 3 "$URL/v1/readyz" >/dev/null 2>&1; }

# capabilities asks the service, with the key in a header read from standard
# input so it is on no command line.
capabilities() {
  [ -s "$KEYFILE" ] || return 1
  printf 'Authorization: Bearer %s\n' "$(cat "$KEYFILE")" |
    curl -sf -m 10 -H @- "$URL/v1/capabilities" 2>/dev/null
}

service_version() {
  capabilities | python3 -c 'import json,sys; print(json.load(sys.stdin)["nuguard_version"])' 2>/dev/null
}

port_listener() { lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -n 1; }

# proxy_warning says when a proxy is set but this NuGuard's clones would not
# use it: checkouts from before the fix kept only PATH, LANG and
# temporary-folder variables for git.
proxy_warning() {
  local d="$1"
  if [ -n "${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}${http_proxy:-}${ALL_PROXY:-}${all_proxy:-}" ] &&
    ! grep -q '_PROXY_ENV' "$d/nuguard/sbom/extractor/git_clone.py" 2>/dev/null; then
    say "${BOLD}Note:${PLAIN} a proxy is set in this shell, but this NuGuard's git clones do not use it, so clones"
    say "fail if github.com is reachable only through it. Update the NuGuard checkout."
  fi
}

# tree_state prints the checkout's full commit and whether it differs from
# it: clean, or dirty with changes to tracked files, or with new files that
# git does not ignore where NuGuard's code and dependencies are (nuguard/,
# pyproject.toml, uv.lock). Untracked notes elsewhere do not change what runs.
tree_state() {
  local d="$1" commit dirty=clean
  commit="$(git -C "$d" rev-parse HEAD 2>/dev/null || echo unknown)"
  if [ -n "$(git -C "$d" status --porcelain --untracked-files=no 2>/dev/null | head -n 1)" ] ||
    [ -n "$(git -C "$d" status --porcelain --untracked-files=all -- nuguard pyproject.toml uv.lock 2>/dev/null | head -n 1)" ]; then
    dirty=dirty
  fi
  printf '%s %s\n' "$commit" "$dirty"
}

# source_id is what results record as provenance.image_digest: git:<commit>,
# with -dirty when the tree differs from it.
source_id() {
  local commit dirty
  read -r commit dirty <<<"$(tree_state "$1")"
  if [ "$dirty" = dirty ]; then printf 'git:%s-dirty\n' "$commit"; else printf 'git:%s\n' "$commit"; fi
}

# listen_addr prints the address the service listens on.
listen_addr() {
  lsof -nP -a -p "$1" -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 { print $9; exit }'
}

start() {
  local d pid
  d="$(nuguard_dir)"
  if pid="$(our_pid)" && ready; then
    say "${GREEN}NuGuard is already running${PLAIN} (pid $pid, $URL)."
    return 0
  fi
  if [ -n "$(port_listener)" ]; then
    die "Port $PORT is already in use by something that is not this NuGuard. Stop it, or choose another port with NUGUARD_PORT."
  fi
  ensure_env "$d"
  ensure_key
  write_config
  write_tools_json
  proxy_warning "$d"
  local src
  src="$(source_id "$d")"
  say "${BOLD}Starting NuGuard on $URL…${PLAIN} (source $src)"
  case "$src" in *-dirty)
    say "${BOLD}Note:${PLAIN} the NuGuard checkout has uncommitted changes; results record $src and cannot be"
    say "reproduced from a commit." ;;
  esac
  # NuGuard's environment first on PATH, then Semgrep's, so its workers
  # never use another Semgrep. The key is not in this environment; only its
  # hash is in the settings.
  ( cd "$STATE"
    env -u VULNFRAMEWORK_NUGUARD_API_KEY -u VULNFRAMEWORK_GITHUB_TOKEN \
      PATH="$VENV/bin:$SEMGREP_VENV/bin:$PATH" NUGUARD_PORT="$PORT" \
      NUGUARD_TOOLS_JSON="$TOOLS_JSON" NUGUARD_IMAGE_DIGEST="$src" \
      nohup "$VENV/bin/nuguard" serve -c "$CONFIG" >>"$LOG" 2>&1 &
    echo $! >"$PIDFILE" )
  printf '%s\n' "$src" >"$SOURCE_FILE"
  chmod 600 "$PIDFILE" "$LOG" "$SOURCE_FILE" 2>/dev/null || true
  for _ in $(seq 1 60); do
    ready && break
    our_pid >/dev/null || die "NuGuard stopped while starting. The end of its log, $LOG:
$(tail -n 15 "$LOG")"
    sleep 1
  done
  ready || { stop >/dev/null 2>&1; die "NuGuard did not become ready within 60 seconds; see $LOG."; }
  local got
  got="$(service_version)" || { stop >/dev/null 2>&1; die "NuGuard is up but /v1/capabilities did not answer with the key; see $LOG."; }
  if [ "$got" != "$PINNED" ]; then
    stop >/dev/null 2>&1
    die "NuGuard reports version $got, but config/tools.lock pins $PINNED. Stopped it. Check out NuGuard $PINNED, or change the pin deliberately."
  fi
  say "${GREEN}  ✓ NuGuard $got ready on $URL${PLAIN} (log: $LOG)"
}

stop() {
  local pid
  if ! pid="$(our_pid)"; then
    rm -f "$PIDFILE"
    say "NuGuard is not running (nothing started by this script)."
    return 0
  fi
  # Only the process in the pid file, never a pattern: a pattern can match
  # the shell that runs this.
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$PIDFILE" "$SOURCE_FILE"
  say "NuGuard stopped."
}

# service_semgrep prints the Semgrep version the running service reports.
service_semgrep() {
  capabilities | python3 -c 'import json,sys
v = {t["name"]: t.get("version") for t in json.load(sys.stdin).get("tools", [])}.get("semgrep")
print(v if v else "null")' 2>/dev/null
}

# status prints one line per fact; real.sh reads "version" and "source".
status() {
  local d pid commit dirty semgrep version="-" readyz=no running=no deps recorded="-" listen="-" svc_semgrep="-"
  d="$(nuguard_dir)"
  read -r commit dirty <<<"$(tree_state "$d")"
  semgrep="$(semgrep_version || true)"
  case "$(cat "$VENV/.vf-deps" 2>/dev/null)" in
    lockfile) deps="from the lockfile (uv sync --frozen, $d/uv.lock)" ;;
    pip) deps="installed with pip: dependencies not from lockfile" ;;
    *) deps="not set up yet (start sets it up)" ;;
  esac
  if pid="$(our_pid)"; then
    running="yes (pid $pid)"
    recorded="$(cat "$SOURCE_FILE" 2>/dev/null || echo unknown)"
    listen="$(listen_addr "$pid")"
    case "$listen" in
      127.0.0.1:* | '[::1]':*) listen="$listen (loopback only)" ;;
      '') listen="unknown" ;;
      *) listen="$listen ${RED}(NOT loopback only)${PLAIN}" ;;
    esac
  fi
  if ready; then
    readyz=ok
    version="$(service_version || echo '? (the key was not accepted)')"
    svc_semgrep="$(service_semgrep || echo '?')"
  fi
  printf 'NuGuard (local)\n'
  printf '  running     %s\n' "$running"
  printf '  url         %s\n' "$URL"
  printf '  listening   %s\n' "$listen"
  printf '  readyz      %s\n' "$readyz"
  printf '  version     %s (config/tools.lock pins %s)\n' "$version" "$PINNED"
  printf '  deps        %s\n' "$deps"
  printf '  semgrep     %s (in %s); the service reports %s\n' "${semgrep:-not installed}" "$SEMGREP_VENV" "$svc_semgrep"
  printf '  source      %s at %s, tree %s\n' "$d" "$commit" "$dirty"
  printf '  recorded    %s (results carry it as provenance.image_digest, vulnframework as nuguard/image)\n' "$recorded"
  printf '  log         %s\n' "$LOG"
  if [ "$dirty" = dirty ]; then
    printf '%sThe NuGuard source has uncommitted changes.%s Results from it cannot be reproduced\n' "$BOLD" "$PLAIN"
    printf 'later from a commit: they come from work that exists only in %s.\n' "$d"
  fi
  if [ "$recorded" != "-" ] && [ "$recorded" != "$(source_id "$d")" ]; then
    printf '%sThe checkout changed since NuGuard started%s (now %s): restart it so results record what runs.\n' \
      "$BOLD" "$PLAIN" "$(source_id "$d")"
  fi
  proxy_warning "$d"
}

# key prints an export line for eval, and only to a pipe or a file, so the
# key does not land on a terminal or in its scrollback.
key() {
  [ -s "$KEYFILE" ] || die "No NuGuard API key yet: run scripts/nuguard-local.sh start first."
  [ ! -t 1 ] || die 'key prints the key only for eval: eval "$(scripts/nuguard-local.sh key)"'
  printf 'export VULNFRAMEWORK_NUGUARD_API_KEY=%q\n' "$(cat "$KEYFILE")"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  status) status ;;
  key) key ;;
  -h | --help | help) usage ;;
  *) usage >&2; exit 2 ;;
esac
