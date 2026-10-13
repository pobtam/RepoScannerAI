#!/usr/bin/env bash
#
# vfctl.sh — manage which of your repositories the real-mode sweep scans.
#
#   ./vfctl.sh repo add acme/api -languages go -tier 1 -test-suite
#   ./vfctl.sh repo add acme/web -languages javascript -lockfile
#   ./vfctl.sh repo list
#   ./vfctl.sh repo remove acme/web
#
# Starts the local database if it is not running (and leaves it running), and
# applies migrations first. Writes only to that database.

set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/real.sh
source scripts/real.sh

real_need_docker
real_pg_up >/dev/null
real_migrate
real_vfctl "$@"
