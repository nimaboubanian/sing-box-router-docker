#!/usr/bin/env bash
# entrypoint.sh — render sing-box config from env vars, then run sing-box.
# `entrypoint.sh render` prints the rendered config to stdout (no network).
set -euo pipefail

log() { printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >&2; }

render_config() {
    echo "render_config: not implemented" >&2
    return 1
}

if [[ "${1:-}" == "render" ]]; then
    render_config
    exit 0
fi

log "run mode: not implemented"
exit 1
