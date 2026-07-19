#!/usr/bin/env bash

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/iosnfcfctl-test.XXXXXX")
trap 'rm -rf -- "$TEMP"' EXIT
STATE="$TEMP/state"
mkdir -m 0700 "$STATE"
CALLS="$TEMP/calls"
FAKE="$TEMP/nfcf-command"

cat >"$FAKE" <<'EOF'
#!/usr/bin/env sh
set -eu
command=$1
printf '%s\n' "$command" >> "$IOS_NFCF_CALL_LOG"
if [ "${IOS_NFCF_FAIL_COMMAND:-}" = "$command" ]; then
    exit 1
fi
case "$command" in
    validate-profile) exit 0 ;;
    fingerprint-profile) printf '%s\n' '0123456789abcdef'; exit 0 ;;
    profile-apply) file=$IOS_NFCF_STATE_DIR/profile.result; text='result=0 profile=loaded active=1 blocks=4' ;;
    profile-status) file=$IOS_NFCF_STATE_DIR/profile.result; text='result=0 profile=loaded active=1 blocks=4' ;;
    profile-clear) file=$IOS_NFCF_STATE_DIR/profile.result; text='result=0 profile=none active=0 cleared=1' ;;
    prewarm-open) file=$IOS_NFCF_STATE_DIR/prewarm.result; text='action=open result=1 error=none' ;;
    prewarm-close) file=$IOS_NFCF_STATE_DIR/prewarm.result; text='action=close result=1 error=none' ;;
    routing-off) file=$IOS_NFCF_STATE_DIR/routing.result; text='result=0 routing=off' ;;
    routing-restore) file=$IOS_NFCF_STATE_DIR/routing.result; text='result=0 routing=restored' ;;
    t3t-patch) file=$IOS_NFCF_STATE_DIR/t3t-route.result; text='result=0 state=patched protocol=T3T' ;;
    t3t-restore) file=$IOS_NFCF_STATE_DIR/t3t-route.result; text='result=0 state=restored protocol=ISO-DEP' ;;
    setce-start) file=$IOS_NFCF_STATE_DIR/setce.result; text='result=0 routing=active' ;;
    setce-stop) file=$IOS_NFCF_STATE_DIR/setce.result; text='result=0 routing=inactive' ;;
    setce-status) file=$IOS_NFCF_STATE_DIR/setce.result; text="result=0 routing=${IOS_NFCF_FAKE_ROUTING:-inactive} health=configured" ;;
    setce-recover) file=$IOS_NFCF_STATE_DIR/setce.result; text='result=0 routing=active health=recovered' ;;
    *) exit 2 ;;
esac
printf '%s pid=%s\n' "$text" "$IOS_NFCF_NFCD_PID" > "$file"
EOF
chmod 0755 "$FAKE"

export IOS_NFCF_STATE_DIR="$STATE"
export IOS_NFCF_COMMAND_HELPER="$FAKE"
export IOS_NFCF_CALL_LOG="$CALLS"
export IOS_NFCF_NFCD_PID=4242
printf 'observer=installed pid=4242\n' > "$STATE/nci-read.ready"
printf 'ready=1 pid=4242\n' > "$STATE/profile.ready"
printf 'record\n' > "$STATE/profile.record"
chmod 0600 "$STATE"/*

sh "$ROOT/scripts/iosnfcfctl" profile apply >"$TEMP/apply.out"
grep -q '"recordFingerprint":"0123456789abcdef"' "$TEMP/apply.out"
grep -q '^fingerprint-profile$' "$CALLS"
grep -q '^0123456789abcdef$' "$STATE/profile.selected"

printf 'different\n' > "$STATE/profile.selected"
if sh "$ROOT/scripts/iosnfcfctl" start >"$TEMP/mismatch.out" 2>&1; then
    echo "start unexpectedly accepted a stale profile marker" >&2
    exit 1
fi
grep -q 'profile record changed' "$TEMP/mismatch.out"
printf '0123456789abcdef\n' > "$STATE/profile.selected"

export IOS_NFCF_FAIL_COMMAND=profile-apply
if sh "$ROOT/scripts/iosnfcfctl" profile apply >"$TEMP/apply-failure.out" 2>&1; then
    echo "profile apply unexpectedly succeeded" >&2
    exit 1
fi
[ ! -e "$STATE/profile.selected" ]
unset IOS_NFCF_FAIL_COMMAND
sh "$ROOT/scripts/iosnfcfctl" profile apply >"$TEMP/reapply.out"

export IOS_NFCF_FAIL_COMMAND=setce-start
if sh "$ROOT/scripts/iosnfcfctl" start >"$TEMP/failure.out" 2>&1; then
    echo "start unexpectedly succeeded" >&2
    exit 1
fi
grep -q '"success":false' "$TEMP/failure.out"
grep -q '^t3t-restore$' "$CALLS"
grep -q '^routing-restore$' "$CALLS"
grep -q '^profile-clear$' "$CALLS"
grep -q '^prewarm-close$' "$CALLS"

: > "$CALLS"
unset IOS_NFCF_FAIL_COMMAND
sh "$ROOT/scripts/iosnfcfctl" start >"$TEMP/start.out"
grep -q '"state":"active"' "$TEMP/start.out"
sh "$ROOT/scripts/iosnfcfctl" stop >"$TEMP/stop.out"
grep -q '"state":"stopped"' "$TEMP/stop.out"
grep -q '^profile-clear$' "$CALLS"
grep -q '^routing-restore$' "$CALLS"

echo "iosnfcfctl_transaction_test: PASS"
