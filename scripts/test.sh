#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CXX=${CXX:-c++}
BUILD_DIR="$ROOT/build/tests"
mkdir -p "$BUILD_DIR"

"$CXX" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
    -I"$ROOT/Sources" -I"$ROOT/Sources/Core" \
    "$ROOT/Sources/Core/NFCFProtocol.cpp" \
    "$ROOT/Sources/Core/NFCFProfileRecord.cpp" \
    "$ROOT/tests/nfcf_protocol_test.cpp" \
    -o "$BUILD_DIR/nfcf_protocol_test"

"$CXX" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
    -I"$ROOT/Sources" -I"$ROOT/Sources/Core" \
    "$ROOT/tests/bounded_append_log_test.cpp" \
    -o "$BUILD_DIR/bounded_append_log_test"

"$CXX" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$ROOT/Sources/Core" -I"$ROOT/Sources/IPC" \
    "$ROOT/Sources/Core/SecureFile.cpp" \
    "$ROOT/Sources/IPC/CommandProtocol.cpp" \
    "$ROOT/tests/command_protocol_test.cpp" \
    -o "$BUILD_DIR/command_protocol_test"

"$BUILD_DIR/nfcf_protocol_test"
"$BUILD_DIR/bounded_append_log_test"
"$BUILD_DIR/command_protocol_test"
bash "$ROOT/tests/iosnfcfctl_transaction_test.sh"
echo "All portable tests passed."
