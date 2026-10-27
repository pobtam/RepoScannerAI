#!/usr/bin/env bash
# scripts/db.sh — back up and restore the local database.
#
#   scripts/db.sh backup  [--target real|demo] [FILE]
#   scripts/db.sh list    [--target real|demo]
#   scripts/db.sh restore [--target real|demo] FILE [--yes]
#
# Targets:
#   real  the database ./run.sh --real uses: container vulnframework-pg on
#         volume vulnframework-pgdata (default). Started for the backup if it
#         is not running, and stopped again afterwards.
#   demo  the local deployment stack (compose project vf-demo, or
#         COMPOSE_PROJECT_NAME): its db container. Started for the backup if
#         it is stopped, and stopped again afterwards.
#
# Backups go to ~/.local/share/vulnframework/backups (VF_BACKUP_DIR
# overrides), readable only by you: they hold your findings, including where
# secrets were found (never their values, which are not stored).
#
# A backup is pg_dump's custom format, checked by reading its table of
# contents back before the command reports success.
#
# A restore never overwrites in place. It loads the backup into a new
# database, checks the findings table is there, and only then swaps the two
# by renaming. The database it replaced is KEPT, renamed
# vulnframework_before_<time>, so a restore can be undone; the command prints
# how to undo it, and how to drop the old copy once you are sure. It refuses
# while the scan worker is running, because a scan finishing during the swap
# would write into the database being replaced.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/real.sh
source "$ROOT/scripts/real.sh"

BACKUP_DIR="${VF_BACKUP_DIR:-$HOME/.local/share/vulnframework/backups}"
DB=vulnframework
DBUSER=vulnframework

usage() {
  sed -n '3,6p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
}

die() { printf '%s%s%s\n' "$real_red" "$*" "$real_plain" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

cmd="${1:-}"; [ -n "$cmd" ] || usage; shift
target=real file="" yes=0
while [ $# -gt 0 ]; do
  case "$1" in
    --target) target="${2:-}"; shift 2 ;;
    --target=*) target="${1#*=}"; shift ;;
    --yes) yes=1; shift ;;
    -h|--help) usage ;;
    -*) die "unknown option $1" ;;
    *) [ -z "$file" ] || die "one file only"; file="$1"; shift ;;
  esac
done

real_need_docker || exit 1

case "$target" in
  real)
    CONTAINER="$REAL_PG_NAME"
    WORKER="${VULNFRAMEWORK_WORKER_CONTAINER:-vulnframework-scanworker}"
    ;;
  demo)
    project="${COMPOSE_PROJECT_NAME:-vf-demo}"
    CONTAINER="${project}-db-1"
    WORKER="${project}-scanworker-1"
    ;;
  *) die "--target must be real or demo" ;;
esac

started=0
cleanup() {
  if [ "$started" = 1 ]; then
    docker stop "$CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# db_up makes sure the target's database is running, remembering whether
# this command started it so it can be stopped again afterwards.
db_up() {
  if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER"; then
    return 0
  fi
  case "$target" in
    real)
      [ "$(real_pg_up)" = 1 ] && started=1 || true
      ;;
    demo)
      docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER" ||
        die "no container $CONTAINER: the demo stack has not been created on this machine"
      docker start "$CONTAINER" >/dev/null
      started=1
      ;;
  esac
  for _ in $(seq 1 60); do
    docker exec "$CONTAINER" pg_isready -U "$DBUSER" >/dev/null 2>&1 && return 0
    sleep 1
  done
  die "the database in $CONTAINER did not become ready"
}

psql_in() { docker exec -i "$CONTAINER" psql -X -q -v ON_ERROR_STOP=1 -U "$DBUSER" "$@"; }

findings_in() {
  psql_in -d "$1" -tAc "SELECT count(*) FROM findings" 2>/dev/null || echo "?"
}

backup() {
  db_up
  mkdir -p "$BACKUP_DIR"
  chmod 700 "$BACKUP_DIR"
  [ -n "$file" ] || file="$BACKUP_DIR/${target}-$(date +%Y%m%d-%H%M%S).dump"
  [ ! -e "$file" ] || die "$file already exists; choose another name"
  local tmp="$file.partial"
  ( umask 077; docker exec "$CONTAINER" pg_dump -Fc -U "$DBUSER" -d "$DB" >"$tmp" ) ||
    { rm -f "$tmp"; die "pg_dump failed"; }
  # Read the table of contents back: a truncated or corrupt file fails here,
  # not on the day it is needed.
  local tables
  tables="$(docker exec -i "$CONTAINER" pg_restore --list <"$tmp" | grep -c ' TABLE ' || true)"
  [ "${tables:-0}" -gt 0 ] || { rm -f "$tmp"; die "the backup has no tables in it; nothing was kept"; }
  mv "$tmp" "$file"
  say "${real_green}Backed up${real_plain} $target database to $file"
  say "  $(du -h "$file" | cut -f1 | tr -d ' '), $tables tables, $(findings_in "$DB") findings"
}

list() {
  [ -d "$BACKUP_DIR" ] || { say "No backups yet (looked in $BACKUP_DIR)."; return; }
  local n=0
  for f in "$BACKUP_DIR"/"$target"-*.dump; do
    [ -e "$f" ] || continue
    printf '%s  %6s  %s\n' "$(date -r "$f" '+%Y-%m-%d %H:%M')" "$(du -h "$f" | cut -f1 | tr -d ' ')" "$f"
    n=$((n + 1))
  done
  [ "$n" -gt 0 ] || say "No $target backups in $BACKUP_DIR."
}

restore() {
  [ -n "$file" ] || die "restore needs the backup file: scripts/db.sh restore [--target $target] FILE"
  [ -f "$file" ] || die "no such file: $file"
  if docker ps --format '{{.Names}}' | grep -qx "$WORKER"; then
    die "the scan worker ($WORKER) is running; stop the app first (Ctrl-C in ./run.sh), then restore"
  fi
  db_up

  local stamp before staging
  stamp="$(date +%Y%m%d_%H%M%S)"
  before="${DB}_before_${stamp}"
  staging="${DB}_restoring_${stamp}"

  say "This replaces the $target database with $file."
  say "The current database ($(findings_in "$DB") findings) is kept as $before, so this can be undone."
  if [ "$yes" != 1 ]; then
    [ -t 0 ] || die "not a terminal: pass --yes to confirm"
    printf 'Type restore to continue: '
    read -r answer
    [ "$answer" = restore ] || die "not restored"
  fi

  psql_in -d postgres -c "CREATE DATABASE \"$staging\" OWNER $DBUSER" >/dev/null
  if ! docker exec -i "$CONTAINER" pg_restore --no-owner --single-transaction --exit-on-error \
      -U "$DBUSER" -d "$staging" <"$file"; then
    psql_in -d postgres -c "DROP DATABASE IF EXISTS \"$staging\"" >/dev/null || true
    die "the backup could not be loaded; nothing was changed"
  fi
  local restored
  restored="$(findings_in "$staging")"
  if [ "$restored" = "?" ]; then
    psql_in -d postgres -c "DROP DATABASE IF EXISTS \"$staging\"" >/dev/null || true
    die "the backup loaded but has no findings table; nothing was changed"
  fi

  # The swap: close other connections (the API reconnects on its next
  # request), then two renames. Nothing is dropped.
  psql_in -d postgres >/dev/null <<SQL
SELECT pg_terminate_backend(pid) FROM pg_stat_activity
 WHERE datname = '$DB' AND pid <> pg_backend_pid();
ALTER DATABASE "$DB" RENAME TO "$before";
ALTER DATABASE "$staging" RENAME TO "$DB";
SQL
  say "${real_green}Restored${real_plain} $file into the $target database: $restored findings."
  say "The previous database is kept as $before."
  say "  To undo it, with the app stopped:"
  say "    docker exec $CONTAINER psql -U $DBUSER -d postgres -c 'ALTER DATABASE $DB RENAME TO ${DB}_restored_${stamp}'"
  say "    docker exec $CONTAINER psql -U $DBUSER -d postgres -c 'ALTER DATABASE $before RENAME TO $DB'"
  say "  Once you are sure, free its space:"
  say "    docker exec $CONTAINER psql -U $DBUSER -d postgres -c 'DROP DATABASE $before'"
  say "Start the app again; it applies any newer migrations to the restored data."
}

case "$cmd" in
  backup) backup ;;
  list) list ;;
  restore) restore ;;
  *) usage ;;
esac
