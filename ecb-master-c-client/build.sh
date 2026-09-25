#!/usr/bin/env bash
set -euo pipefail

cmake -B build -DCMAKE_BUILD_TYPE=Release "$@"
cmake --build build
