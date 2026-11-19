#!/usr/bin/env bash
#
# verify-image.sh IMAGE TOOLS_LOCK — check a scanner image against tools.lock.
#
# Exits 0 when every tool in tools.lock is in the image at exactly the pinned
# version, and 1 otherwise, naming each mismatch. It NEVER builds or pulls: a
# stale image is reported for a human to rebuild, because every run records the
# tool versions it used (VM-F-202), and a run recorded against versions the
# image does not contain is a wrong record, not a slow one.
#
# The Dockerfile's own final step only checks that each tool runs, not its
# version, so this is the version check.
#
# Go tools are read from their embedded build info (`go version -m`), which is
# what `go install tool@version` recorded — gitleaks' own `version` command
# prints "version is set by build process" in this image, so its self-report
# cannot be used.

set -euo pipefail

image="${1:?usage: verify-image.sh IMAGE TOOLS_LOCK}"
lock="${2:?usage: verify-image.sh IMAGE TOOLS_LOCK}"

if ! docker image inspect "$image" >/dev/null 2>&1; then
  echo "scanner image $image is not present locally."
  echo "Build it with: docker build -t $image vulnframework/deploy/scanner"
  exit 1
fi

# One container, every version, one line each: "<tool> <version>".
actual="$(docker run --rm --network none --entrypoint bash "$image" -c '
  modver() { go version -m "/usr/local/bin/$1" 2>/dev/null | awk "\$1==\"mod\"{print \$3; exit}"; }
  echo "govulncheck $(modver govulncheck)"
  echo "gosec $(modver gosec)"
  echo "staticcheck $(modver staticcheck)"
  echo "osv-scanner $(modver osv-scanner)"
  echo "gitleaks $(modver gitleaks)"
  echo "trivy v$(trivy --version 2>/dev/null | awk "/^Version:/{print \$2; exit}")"
  echo "semgrep $(SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version 2>/dev/null | tail -n 1)"
  echo "npm-audit $(npm --version 2>/dev/null)"
')"

status=0
checked=0
while read -r kind name want _; do
  [ "$kind" = "tool" ] || continue
  if [ "$name" = "actions-pin" ]; then
    # Not a binary: the adapter is compiled into the orchestrator and takes
    # its version from tools.lock itself, so there is nothing in the image
    # to disagree with.
    printf '  ok        %-12s %s (built into the orchestrator)\n' "$name" "$want"
    checked=$((checked + 1))
    continue
  fi
  if [ "$name" = "nuguard" ]; then
    # A remote service, not part of this image: its version is checked
    # against the service itself, at start-up and on every result.
    printf '  ok        %-12s %s (remote service, checked against the service)\n' "$name" "$want"
    checked=$((checked + 1))
    continue
  fi
  got="$(printf '%s\n' "$actual" | awk -v n="$name" '$1==n{print $2; exit}')"
  if [ -z "$got" ]; then
    printf '  MISSING   %-12s tools.lock pins %s; the image does not report it\n' "$name" "$want"
    status=1
  elif [ "$got" != "$want" ]; then
    printf '  STALE     %-12s tools.lock pins %s; the image has %s\n' "$name" "$want" "$got"
    status=1
  else
    printf '  ok        %-12s %s\n' "$name" "$got"
  fi
  checked=$((checked + 1))
done < "$lock"

if [ "$checked" -eq 0 ]; then
  echo "no tools found in $lock"
  exit 1
fi
if [ "$status" -ne 0 ]; then
  echo
  echo "The scanner image does not match $lock. Not rebuilding it automatically."
  echo "Rebuild deliberately, then run again:"
  echo "  docker build -t $image vulnframework/deploy/scanner"
fi
exit "$status"
