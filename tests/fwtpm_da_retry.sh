#!/bin/bash
#
# fwtpm_da_retry.sh - isolated end-to-end check of the fwTPM Dictionary Attack
# TPM_RC_RETRY (daUsed) path.
#
# Requires a build with -DFWTPM_DA_USED_RETRY: the fwTPM server then returns
# TPM_RC_RETRY on the first DA-protected (non-noDA) auth use while it persists
# the daUsed flag. That breaks non-retry-aware clients, so this harness starts
# the server and runs ONLY examples/management/da_check -lockout, which rides
# through RC_RETRY, drives lockout, and recovers.
#
# Exit: 0 = pass, 77 = skip (not built / wrong build), non-zero = fail
#

BUILD_DIR="$(pwd)"
SERVER="$BUILD_DIR/src/fwtpm/fwtpm_server"
DA_CHECK="$BUILD_DIR/examples/management/da_check"
OPTIONS="$BUILD_DIR/wolftpm/options.h"
OUT="/tmp/fwtpm_da_retry_$$.out"
PID=""

cleanup() {
    [ -n "$PID" ] && kill "$PID" 2>/dev/null
    rm -f "$OUT" "/tmp/fwtpm_da_srv_$$.log"
}
trap cleanup EXIT

if [ ! -x "$SERVER" ] || [ ! -x "$DA_CHECK" ]; then
    echo "SKIP: fwtpm_server or da_check not built"
    exit 77
fi

# The RC_RETRY emulation only exists when built with -DFWTPM_DA_USED_RETRY.
if [ ! -f "$OPTIONS" ] || \
        ! grep -q "^#define FWTPM_DA_USED_RETRY" "$OPTIONS"; then
    echo "SKIP: build lacks FWTPM_DA_USED_RETRY"
    exit 77
fi

IS_SWTPM=0
if [ -f "$OPTIONS" ] && grep -q "^#define WOLFTPM_SWTPM" "$OPTIONS"; then
    IS_SWTPM=1
fi

rm -f "$BUILD_DIR/fwtpm_nv.bin" /tmp/fwtpm.shm

if [ $IS_SWTPM -eq 1 ]; then
    PORT="${TPM2_SWTPM_PORT:-2371}"
    "$SERVER" --clear --port "$PORT" --platform-port "$((PORT + 1))" \
        >/tmp/fwtpm_da_srv_$$.log 2>&1 &
    PID=$!
    export TPM2_SWTPM_PORT="$PORT"
    for i in $(seq 1 500); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
            exec 3>&- 3<&-
            break
        fi
        sleep 0.01
    done
else
    "$SERVER" --clear >/tmp/fwtpm_da_srv_$$.log 2>&1 &
    PID=$!
    elapsed=0
    while [ ! -e /tmp/fwtpm.shm ] && [ $elapsed -lt 500 ]; do
        sleep 0.01
        elapsed=$((elapsed + 1))
    done
fi

if ! kill -0 "$PID" 2>/dev/null; then
    echo "FAIL: fwtpm_server failed to start"
    cat /tmp/fwtpm_da_srv_$$.log 2>/dev/null
    exit 1
fi

"$DA_CHECK" -lockout >"$OUT" 2>&1
RESULT=$?
cat "$OUT"

if [ $RESULT -ne 0 ]; then
    echo "FAIL: da_check -lockout exited $RESULT"
    exit 1
fi
if ! grep -q "resubmitting" "$OUT"; then
    echo "FAIL: expected TPM_RC_RETRY resubmit was not observed"
    exit 1
fi
if ! grep -q "Recovered via DictionaryAttackLockReset" "$OUT"; then
    echo "FAIL: lockout recovery path did not run"
    exit 1
fi

echo "PASS: fwTPM DA RC_RETRY + lockout end-to-end"
exit 0
