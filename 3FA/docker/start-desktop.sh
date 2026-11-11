#!/usr/bin/env bash
set -euo pipefail

mkdir -p "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
children=()

cleanup() {
    if (( ${#children[@]} )); then
        kill "${children[@]}" 2>/dev/null || true
        wait "${children[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM

Xvfb "$DISPLAY" -screen 0 1600x1000x24 -nolisten tcp &
children+=("$!")
for (( attempt=0; attempt<50; ++attempt )); do
    if xdpyinfo >/dev/null 2>&1; then break; fi
    sleep 0.1
done
xdpyinfo >/dev/null

openbox &
children+=("$!")
x11vnc -localhost -rfbport 5900 -forever -shared -nopw -noxdamage -quiet &
children+=("$!")
websockify --web /usr/share/novnc --auth-plugin ExpectOrigin \
    --auth-source 'http://127.0.0.1:6080 http://localhost:6080' 6080 127.0.0.1:5900 &
children+=("$!")

cd /opt/threefa/build
./3FA &
children+=("$!")
wait -n "${children[@]}"
