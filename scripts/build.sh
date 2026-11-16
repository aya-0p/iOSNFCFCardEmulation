#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
THEOS=${THEOS:-"$HOME/theos"}
TARGET=${TARGET:-"arm64e-apple-ios17.6.1"}

if [[ "$(uname -s)" == "Darwin" ]]; then
    TOOLCHAIN=${TOOLCHAIN:-"$(dirname "$(xcrun -f clang++)")"}
    LDID=${LDID:-ldid}
    SDK=${SDK:-"$(find -L "$THEOS/sdks" -maxdepth 1 -type d -name 'iPhoneOS*.sdk' | sort | tail -n 1)"}
    LINKER_FLAGS=(-Wl,-no_warn_inits)
    HELPER_LINKER_FLAGS=()
    SHA256SUM=${SHA256SUM:-shasum}
    SHA256_ARGS=(-a 256)
else
    TOOLCHAIN=${TOOLCHAIN:-"$THEOS/toolchain/linux/iphone/bin"}
    LDID=${LDID:-"$THEOS/toolchain/linux/iphone/bin/ldid"}
    SDK=${SDK:-"$THEOS/sdks/iPhoneOS16.5.sdk"}
    LINKER_FLAGS=(-Wl,-add_split_seg_info -Wl,-no_auth_data -Wl,-no_warn_inits)
    HELPER_LINKER_FLAGS=(-Wl,-no_auth_data)
    SHA256SUM=${SHA256SUM:-sha256sum}
    SHA256_ARGS=()
fi

CLANG=${CLANG:-"$TOOLCHAIN/clang++"}
CLANG_C=${CLANG_C:-"$TOOLCHAIN/clang"}

if [[ ! -d "$SDK" ]]; then
    echo "Set SDK to a legally obtained iPhoneOS SDK directory." >&2
    exit 1
fi

for command in "$CLANG" "$CLANG_C" "$LDID" dpkg-deb install "$SHA256SUM"; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required command not found: $command" >&2
        exit 1
    fi
done

PACKAGE=$(awk '$1 == "Package:" { print $2 }' "$ROOT/Packaging/control")
VERSION=$(awk '$1 == "Version:" { print $2 }' "$ROOT/Packaging/control")
if [[ -z "$PACKAGE" || -z "$VERSION" ]]; then
    echo "Packaging/control does not contain Package and Version fields." >&2
    exit 1
fi

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/ios-nfcf-card-emulation.XXXXXX")
trap 'rm -rf -- "$WORK_DIR"' EXIT

ARTIFACT="$WORK_DIR/iOSNFCFCardEmulation.dylib"
HELPER_STAGE="$WORK_DIR/helpers"
STAGE="$WORK_DIR/stage"
DIST="$ROOT/dist"
OUTPUT="$DIST/${PACKAGE}_${VERSION}_iphoneos-arm64.deb"
mkdir -p "$HELPER_STAGE" "$DIST"

"$CLANG" -std=c++17 -fblocks -O2 -Wall -Wextra -Werror -dynamiclib \
    -target "$TARGET" -isysroot "$SDK" \
    -F"$SDK/System/Library/Frameworks" \
    -I"$ROOT/Sources" \
    -I"$ROOT/Sources/Core" \
    -I"$ROOT/Sources/IPC" \
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
    -framework Foundation -framework CoreFoundation \
    "${LINKER_FLAGS[@]}" \
    -Wl,-install_name,/var/jb/Library/MobileSubstrate/DynamicLibraries/iOSNFCFCardEmulation.dylib \
    -o "$ARTIFACT"
"$LDID" -S "$ARTIFACT"

build_cpp_helper() {
    local output_name=$1
    shift
    "$CLANG" -std=c++17 -O2 -Wall -Wextra -Werror -target "$TARGET" \
        -isysroot "$SDK" -I"$ROOT/Sources" -I"$ROOT/Sources/Core" \
        -I"$ROOT/Sources/IPC" "${HELPER_LINKER_FLAGS[@]}" "$@" \
        -o "$HELPER_STAGE/$output_name"
    "$LDID" -S "$HELPER_STAGE/$output_name"
}

"$CLANG_C" -fblocks -O2 -Wall -Wextra -Werror -target "$TARGET" \
    -isysroot "$SDK" "${HELPER_LINKER_FLAGS[@]}" \
    "$ROOT/Helpers/nfcd_xpc_wake.c" -framework Foundation \
    -o "$HELPER_STAGE/nfcd-xpc-wake"
"$LDID" -S "$HELPER_STAGE/nfcd-xpc-wake"
build_cpp_helper nfcf-command \
    "$ROOT/Helpers/nfcf_command.cpp" \
    "$ROOT/Sources/IPC/CommandProtocol.cpp" \
    "$ROOT/Sources/Core/SecureFile.cpp" \
    "$ROOT/Sources/Core/NFCFProfileRecord.cpp"

mkdir -p \
    "$STAGE/DEBIAN" \
    "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries" \
    "$STAGE/var/jb/usr/bin" \
    "$STAGE/var/jb/usr/libexec/iosnfcf" \
    "$STAGE/var/jb/usr/share/org.hoshitsugi.iosnfcfcardemulation" \
    "$STAGE/var/jb/usr/share/doc/$PACKAGE"

install -m 0644 "$ROOT/Packaging/control" "$STAGE/DEBIAN/control"
install -m 0755 "$ROOT/scripts/iosnfcfctl" \
    "$STAGE/var/jb/usr/bin/iosnfcfctl"
install -m 0644 "$ARTIFACT" \
    "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries/iOSNFCFCardEmulation.dylib"
install -m 0644 "$ROOT/Packaging/iOSNFCFCardEmulation.plist" \
    "$STAGE/var/jb/Library/MobileSubstrate/DynamicLibraries/iOSNFCFCardEmulation.plist"
install -m 0644 "$ROOT/Resources/PackageIcon.png" \
    "$STAGE/var/jb/usr/share/org.hoshitsugi.iosnfcfcardemulation/PackageIcon.png"
install -m 0755 "$HELPER_STAGE"/* "$STAGE/var/jb/usr/libexec/iosnfcf/"
install -m 0755 "$ROOT/Packaging/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$ROOT/Packaging/prerm" "$STAGE/DEBIAN/prerm"
install -m 0755 "$ROOT/Packaging/postrm" "$STAGE/DEBIAN/postrm"
install -m 0644 "$ROOT/LICENSE" \
    "$STAGE/var/jb/usr/share/doc/$PACKAGE/LICENSE"

dpkg-deb --build --root-owner-group "$STAGE" "$OUTPUT"
"$SHA256SUM" "${SHA256_ARGS[@]}" "$ARTIFACT" "$OUTPUT"
