#!/usr/bin/env bash
# deploy/build.sh — build every image the stack runs, on this machine.
#
# VF_IMAGE_TAG names the tag (default v1, what deploy/compose.yaml runs). A
# test of an unmerged branch builds under another tag, so a running stack's
# images, and the database they would migrate, are left alone.
#
# The scanner image is built from vulnframework/deploy/scanner and checked
# against config/tools.lock with verify-image.sh before anything is built on
# top of it: a sweep image over the wrong scanners would make every run
# record wrong.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCANNER="$(awk '$1=="image"{print $2; exit}' vulnframework/config/tools.lock)"

if [ "${SKIP_SCANNER:-0}" != "1" ]; then
  echo "building the scanner image $SCANNER (this takes a while the first time)"
  docker build -t "$SCANNER" vulnframework/deploy/scanner
fi
vulnframework/deploy/scanner/verify-image.sh "$SCANNER" vulnframework/config/tools.lock

tag="${VF_IMAGE_TAG:-v1}"
echo "building vulnframework-api, -web and -sweep:$tag"
docker build -f deploy/Dockerfile --target api -t "vulnframework-api:$tag" .
docker build -f deploy/Dockerfile --target web -t "vulnframework-web:$tag" .
docker build -f deploy/Dockerfile --target sweep --build-arg "SCANNER_IMAGE=$SCANNER" -t "vulnframework-sweep:$tag" .
echo "built. Start the stack: docker compose -f deploy/compose.yaml up -d"
