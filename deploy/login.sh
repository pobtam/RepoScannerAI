#!/usr/bin/env bash
# deploy/login.sh — set or read the stack's login password without it
# appearing in a terminal log, a command line or the repository.
#
#   deploy/login.sh reset [--env FILE]   new random password; the stack's
#                                        settings get its hash
#   deploy/login.sh copy  [--env FILE]   copy the password to the clipboard
#   deploy/login.sh show  [--env FILE]   print it (only on a terminal)
#
# FILE is the stack's settings file, by default
# ~/.config/vulnframework/demo/env (VF_ENV_FILE overrides). The password is
# kept beside it, in login-password, readable only by you; the settings file
# holds only its bcrypt hash, in LOGIN_HASH. The password reaches Caddy's
# hash-password on standard input, never as an argument.
#
# reset keeps the previous settings as FILE.before-reset. The new password
# takes effect when the stack is next created:
#   docker compose --env-file FILE -p vf-demo -f deploy/compose.yaml up -d
set -euo pipefail

CADDY=caddy:2.8.4-alpine
cmd="${1:-}"; [ $# -gt 0 ] && shift
env_file="${VF_ENV_FILE:-$HOME/.config/vulnframework/demo/env}"
while [ $# -gt 0 ]; do
  case "$1" in
    --env) env_file="${2:-}"; shift 2 ;;
    --env=*) env_file="${1#*=}"; shift ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
pw_file="$(dirname "$env_file")/login-password"

die() { echo "$*" >&2; exit 1; }

reset() {
  [ -f "$env_file" ] || die "no settings file at $env_file"
  grep -q '^LOGIN_HASH=' "$env_file" || die "$env_file has no LOGIN_HASH line"
  local pw hash tmp
  # 24 characters from a 144-bit random value, letters and digits only so it
  # survives copying anywhere.
  pw="$(openssl rand -base64 36 | tr -dc 'A-Za-z0-9' | head -c 24)"
  [ "${#pw}" -eq 24 ] || die "could not generate a password"
  hash="$(printf '%s\n' "$pw" | docker run --rm -i "$CADDY" caddy hash-password)"
  case "$hash" in '$2a$'*) ;; *) die "caddy hash-password gave no bcrypt hash" ;; esac

  ( umask 077
    cp -p "$env_file" "$env_file.before-reset"
    tmp="$env_file.tmp"
    # Single quotes: compose would otherwise read the $ in the hash as
    # variables.
    awk -v h="$hash" '/^LOGIN_HASH=/{print "LOGIN_HASH='\''" h "'\''"; next} {print}' "$env_file" >"$tmp"
    mv "$tmp" "$env_file"
    printf '%s\n' "$pw" >"$pw_file.tmp"
    mv "$pw_file.tmp" "$pw_file" )
  chmod 600 "$env_file" "$env_file.before-reset" "$pw_file"
  echo "New login password saved in $pw_file (not shown)."
  echo "Its hash is in $env_file; the old settings are in $env_file.before-reset."
  echo "Recreate the stack for it to take effect:"
  echo "  docker compose --env-file $env_file -p vf-demo -f deploy/compose.yaml up -d"
}

need_pw() { [ -f "$pw_file" ] || die "no saved password at $pw_file: run deploy/login.sh reset"; }

case "$cmd" in
  reset) reset ;;
  copy)
    need_pw
    command -v pbcopy >/dev/null || die "no pbcopy here; use show on a terminal"
    tr -d '\n' <"$pw_file" | pbcopy
    echo "Copied the login password to the clipboard. The login name is $(sed -n "s/^LOGIN_USER=//p" "$env_file")."
    ;;
  show)
    need_pw
    [ -t 1 ] || die "show prints only to a terminal, so the password does not land in a log; use copy"
    cat "$pw_file"
    ;;
  *) sed -n '3,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
