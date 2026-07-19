#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CXX=${CXX:-c++}
BUILD_DIR="$ROOT/build/benchmarks"
mkdir -p "$BUILD_DIR"

"$CXX" -std=c++17 -O3 -DNDEBUG -Wall -Wextra -pthread \
    -I"$ROOT/Sources" -I"$ROOT/Sources/Core" \
    "$ROOT/Sources/Core/NFCFProtocol.cpp" \
    "$ROOT/Sources/Core/NFCFProfileRecord.cpp" \
    "$ROOT/tests/nfcf_protocol_benchmark.cpp" \
    -o "$BUILD_DIR/nfcf_protocol_benchmark"

"$BUILD_DIR/nfcf_protocol_benchmark"
