#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
CLANG=$(xcrun -f clang++)
BUILD_DIR="$ROOT/build/ios-ci"
mkdir -p "$BUILD_DIR"

"$CLANG" -std=c++17 -fblocks -O2 -Wall -Wextra -Werror -dynamiclib \
    -target arm64-apple-ios16.0 -isysroot "$SDK" \
    -F"$SDK/System/Library/Frameworks" \
    -I"$ROOT/Sources" -I"$ROOT/Sources/Core" \
    -I"$ROOT/Sources/IPC" -I"$ROOT/Sources/Platform" \
    "$ROOT/Sources/Core/BackendRuntime.mm" \
    "$ROOT/Sources/NFCD/PrewarmController.mm" \
    "$ROOT/Sources/NFCD/RoutingController.mm" \
    "$ROOT/Sources/NFCD/CardEmulationController.mm" \
    "$ROOT/Sources/NFCD/T3TRoutePatch.mm" \
    "$ROOT/Sources/NFCD/StackObserver.mm" \
    "$ROOT/Sources/NFCD/NCIObserver.mm" \
    "$ROOT/Sources/NFCD/NCIReadObserver.mm" \
    "$ROOT/Sources/NFCD/ProfileManager.mm" \
    "$ROOT/Sources/Core/NFCFProtocol.cpp" \
    "$ROOT/Sources/Core/NFCFProfileRecord.cpp" \
    "$ROOT/Sources/Core/SecureFile.cpp" \
    "$ROOT/Sources/IPC/CommandProtocol.cpp" \
    -framework Foundation -framework CoreFoundation -Wl,-no_warn_inits \
    -Wl,-install_name,/var/jb/Library/MobileSubstrate/DynamicLibraries/iOSNFCFCardEmulation.dylib \
    -o "$BUILD_DIR/iOSNFCFCardEmulation.dylib"

"$CLANG" -std=c++17 -O2 -Wall -Wextra -Werror \
    -target arm64-apple-ios16.0 -isysroot "$SDK" \
    -I"$ROOT/Sources" -I"$ROOT/Sources/Core" -I"$ROOT/Sources/IPC" \
    "$ROOT/Helpers/nfcf_command.cpp" \
    "$ROOT/Sources/IPC/CommandProtocol.cpp" \
    "$ROOT/Sources/Core/SecureFile.cpp" \
    "$ROOT/Sources/Core/NFCFProfileRecord.cpp" \
    -o "$BUILD_DIR/nfcf-command"

"$(xcrun -f clang)" -fblocks -O2 -Wall -Wextra -Werror \
    -target arm64-apple-ios16.0 -isysroot "$SDK" \
    "$ROOT/Helpers/nfcd_xpc_wake.c" -framework Foundation \
    -o "$BUILD_DIR/nfcd-xpc-wake"
