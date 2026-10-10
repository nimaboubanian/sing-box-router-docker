#!/usr/bin/env bash
# build.sh — build the image via buildx on the host network.
# Direct network access is the default; set BUILD_PROXY (e.g.
# socks5://127.0.0.1:1081) to route the build through a proxy instead.
# NOTE: use socks5://, NOT socks5h:// — buildkit's Go ignores the socks5h
# scheme in HTTP(S)_PROXY and falls back to a direct (here: 403'd) fetch.
set -euo pipefail

BUILDER=router-build-$$

trap 'docker buildx rm --force "$BUILDER" >/dev/null 2>&1 || true' EXIT

PROXY_ARGS=()
if [[ -n "${BUILD_PROXY:-}" ]]; then
    PROXY_ARGS=(--driver-opt "env.HTTP_PROXY=$BUILD_PROXY" --driver-opt "env.HTTPS_PROXY=$BUILD_PROXY")
fi

docker buildx create --name "$BUILDER" --driver docker-container \
    --driver-opt network=host \
    "${PROXY_ARGS[@]}" >/dev/null

export BUILDX_BUILDER="$BUILDER"
docker compose build "$@"
echo done
