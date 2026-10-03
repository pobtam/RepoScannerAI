#
# Prove the layout guards can fail (OQ-UI-04).
#
# A layout guard that cannot fail is decoration, and the defect that prompted
# all of this passed 73 tests, a type checker and a Zod validator. So each
# guard is checked against a deliberate break of the kind it exists to catch:
# a rule is appended to the real stylesheet, the geometry tests are run, and
# the run must go RED. The stylesheet is restored either way.
#
# Run it from the reportui directory:
#
#   bash scripts/layout-break-check.sh
#
# It needs Chrome or Chromium, like the guards themselves. Without one the
# geometry half does not run and every break will read as uncaught, which is
# correct: nothing was measured.

set -uo pipefail
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
CSS=src/styles.css
break_css() {
  local name="$1" rule="$2"
  cp "$CSS" "$CSS.bak"
  printf '\n%s\n' "$rule" >> "$CSS"
  npx vitest run src/features/views-layout.test.tsx >/tmp/vt.log 2>&1; local rc=$?
  mv "$CSS.bak" "$CSS"
  if [ $rc -ne 0 ]; then
    echo "  ✓ $name — caught"; PASS=$((PASS+1))
    grep -oE '(overflows|overlaps|degenerate|clipped|descendantCount)' /tmp/vt.log | sort -u | head -2 | sed 's/^/      via /'
  else
    echo "  ✗ $name — NOT CAUGHT"; FAIL=$((FAIL+1))
  fi
}

# Containment: push a figure out of its grid, as a too-wide value would.
break_css "a figure overflows the grid" ".figures .figure:first-child { min-width: 2000px; }"

# Overlap: the exact shape of the findings-table defect — children lifted out
# of the flow and positioned by offset.
break_css "figures are positioned absolutely and collide" ".figures { position: relative; } .figures > .figure { position: static; margin-top: -60px; }"

# Degenerate: an element carrying text collapsed to nothing.
break_css "a figure label collapses to zero height" ".figure-label { height: 0; overflow: hidden; display: block; }"

# Clipped: a value too wide for the box that holds it, with its caveat.
break_css "a figure value is clipped by its box" ".figure-value { display: block; width: 8px; overflow-x: hidden; white-space: nowrap; }"

# The coverage strip, as a table: the same `display: block` that broke the
# findings table.
# NOTE: the findings-table defect transplanted verbatim — `tbody { display:
# block }` — does NOT break this table, and that was measured rather than
# assumed. The collapse works by the anonymous table-cell landing in column
# one, which needs a <thead> defining a narrow column one to land in. The
# coverage history has no thead, so the anonymous cell takes the full width
# and the rows still span the table. It is structurally immune to that exact
# defect.
#
# So the guard is proven against a break that DOES apply to a thead-less
# table: rows that no longer span it.
break_css "the coverage history rows no longer span the table" ".coverage-history tbody { display: block; } .coverage-history tbody tr { display: table; width: 120px; }"

# And the overlap half of that same defect: rows positioned by offset.
break_css "the coverage history rows overlap" ".coverage-history tbody { position: relative; display: block; height: 40px; } .coverage-history tbody tr { position: absolute; top: 0; display: table; width: 100%; }"

# The wave graph drawn outside its own viewport.
break_css "the wave graph spills past its frame" ".wave-graph { width: 100px; overflow: visible; }"

echo "=== $PASS caught, $FAIL not ==="
