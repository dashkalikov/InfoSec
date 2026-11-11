#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ! ${DISPLAY:-} =~ ^(:|unix:)([0-9]+)(\.[0-9]+)?$ ]]; then
    echo 'Run this script in an X11/XWayland desktop session or in WSLg.' >&2
    exit 1
fi
if [[ ! -S /tmp/.X11-unix/X${BASH_REMATCH[2]} ]]; then
    echo 'The local X11 socket is missing. Start the graphical session and try again.' >&2
    exit 1
fi

if ! docker info --format '{{.OSType}}' | grep -qx linux; then
    echo 'Start Docker with Linux containers. In WSL, enable Docker Desktop integration for this distribution.' >&2
    exit 1
fi

export THREEFA_X11_SOCKET_DIR
THREEFA_X11_SOCKET_DIR=$(realpath -- /tmp/.X11-unix)
auth_dir=$(mktemp -d)
export THREEFA_XAUTH_FILE="$auth_dir/Xauthority"
trap 'rm -f -- "$THREEFA_XAUTH_FILE"; rmdir -- "$auth_dir"' EXIT
touch -- "$THREEFA_XAUTH_FILE"

host_auth=${XAUTHORITY:-$HOME/.Xauthority}
if [[ -r "$host_auth" ]]; then
    if ! command -v xauth >/dev/null; then
        echo 'Install xauth to pass your desktop session cookie to the container.' >&2
        exit 1
    fi
    # The container has a different hostname. Only copy the cookie for this display.
    xauth -f "$host_auth" nlist "$DISPLAY" | sed 's/^..../ffff/' | xauth -f "$THREEFA_XAUTH_FILE" nmerge -
fi
chmod 644 -- "$THREEFA_XAUTH_FILE"

docker compose -f "$project_dir/3FA/compose.yaml" -f "$project_dir/3FA/compose.desktop.yaml" \
    up --build --exit-code-from app
