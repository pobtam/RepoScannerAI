# scripts/launch.sh — how run.sh starts the API server and the interface's
# dev server. Sourced by run.sh, and by scripts/test-real-cmdlines.sh, which
# checks what they start with; not run directly.
#
# Neither needs a credential: the scan containers do (real_worker_start,
# real_sweep), and they get theirs by name from run.sh's own environment.
# So both start with the NuGuard API key and the GitHub token removed from
# their environment, whatever this shell has exported.

LAUNCH_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAUNCH_SCRUB=(env -u VULNFRAMEWORK_NUGUARD_API_KEY -u VULNFRAMEWORK_GITHUB_TOKEN)

# launch_api ARGS... replaces the calling shell with the API server, so it
# is always run as `launch_api ... &`: the background job's pid is then go
# run's, and run.sh's stop can end the compiled server it starts.
launch_api() {
  cd "$LAUNCH_ROOT/vulnframework" && exec "${LAUNCH_SCRUB[@]}" go run ./cmd/apiserver "$@"
}

# launch_ui exec|wait UI_PORT API_PORT runs the interface's dev server.
# exec replaces this shell with it; wait keeps the shell, so its traps run
# when the dev server ends.
launch_ui() {
  local how="$1" ui_port="$2" api_port="$3"
  cd "$LAUNCH_ROOT/reportui" || return 1
  if [ "$how" = exec ]; then
    PORT="$ui_port" API_URL="http://127.0.0.1:${api_port}" \
      exec "${LAUNCH_SCRUB[@]}" npm run dev -- --host 127.0.0.1 --port "$ui_port" --strictPort
  fi
  PORT="$ui_port" API_URL="http://127.0.0.1:${api_port}" \
    "${LAUNCH_SCRUB[@]}" npm run dev -- --host 127.0.0.1 --port "$ui_port" --strictPort
}
