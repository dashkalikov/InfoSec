#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir="$project_dir/build-linux"

cmake -S "$project_dir" -B "$build_dir" -DCMAKE_BUILD_TYPE=Release
cmake --build "$build_dir" --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-2}"

if [[ -x "$project_dir/.venv-linux/bin/python3" ]]; then
    export PATH="$project_dir/.venv-linux/bin:$PATH"
fi

cd -- "$build_dir"
exec ./3FA "$@"
