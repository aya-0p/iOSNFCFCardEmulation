#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Run this check from a Git worktree." >&2
    exit 1
fi

failed=0
while IFS= read -r path; do
    case "$path" in
        *.apk|*.deb|*.dylib|*.ipa|*.mobileprovision|*.p12|*.record|*.zip|\
        */known_hosts|known_hosts|*/id_*|id_*)
            echo "Forbidden release artifact: $path" >&2
            failed=1
            ;;
    esac
    size=$(wc -c < "$path")
    if [[ "$size" -gt 2097152 ]]; then
        echo "Tracked file exceeds 2 MiB: $path ($size bytes)" >&2
        failed=1
    fi
done < <(git ls-files)

if git grep -I -n -E -- \
    'BEGIN (OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}' \
    -- ':!scripts/check-source.sh'; then
    echo "Possible credential found in tracked content." >&2
    failed=1
fi

if git grep -I -n -E -- \
    'C:\\Users\\|/home/nabej|felica-ios-poc|SumafoDeGakuseisyou-analysis' \
    -- ':!scripts/check-source.sh'; then
    echo "Machine-local path found in tracked content." >&2
    failed=1
fi

if git grep -I -n -i -E -- \
    'student|学生証|1a8b|fe00|--card|hscard|iosdegakuseisyo' \
    -- ':!scripts/check-source.sh'; then
    echo "Application-specific NFC-F values found in the backend." >&2
    failed=1
fi

git diff --cached --check
git diff --check

mapfile -t constructors < <(grep -R -l \
    '__attribute__((constructor))' Sources || true)
if [[ "${#constructors[@]}" -ne 1 ||
      "${constructors[0]:-}" != "Sources/Core/BackendRuntime.mm" ]]; then
    echo "The backend must have exactly one explicit runtime initializer." >&2
    printf 'Found: %s\n' "${constructors[*]:-none}" >&2
    failed=1
fi

exit "$failed"
