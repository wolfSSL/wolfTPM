#!/bin/bash
#
# fwtpm_check.sh - TPM make check entry point
#
# Handles three modes:
#   1. --enable-fwtpm --enable-swtpm: starts fwtpm_server on random port
#   2. --enable-fwtpm (TIS/SHM):      starts fwtpm_server with shared memory
#   3. --enable-swtpm (no fwtpm):     uses existing external TPM server
#
# Runs unit.test and run_examples.sh against the TPM.
# Exit: 0 = pass, 77 = skip, non-zero = fail
#

BUILD_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FWTPM_SERVER="$BUILD_DIR/src/fwtpm/fwtpm_server"
UNIT_TEST="$BUILD_DIR/tests/unit.test"
RUN_EXAMPLES="$SRC_DIR/examples/run_examples.sh"
PID_FILE="/tmp/fwtpm_check_$$.pid"

PASS=0
FAIL=0
SKIP=0
STARTED_SERVER=0
SKIP_EXAMPLES=0

# --- Helpers ---

# Wait for a TCP port to be listening
# Uses ss/netstat to check without connecting (nc -z would consume the accept slot)
# Port separator in netstat output is ':' on Linux and '.' on macOS.
wait_for_port() {
    local port="$1" timeout="${2:-500}" elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if command -v ss >/dev/null 2>&1; then
            ss -tln 2>/dev/null | grep -qE "[:.]${port} " && return 0
        elif netstat -an 2>/dev/null | grep -qE "[:.]${port} .*LISTEN"; then
            return 0
        fi
        sleep 0.01
        elapsed=$((elapsed + 1))
    done
    return 1
}

# Check if a port is in use.
# Returns: 0 = in use, 1 = free, 2 = unknown (no probe tool available)
check_port_in_use() {
    local port="$1"
    if command -v nc >/dev/null 2>&1; then
        nc -z localhost "$port" 2>/dev/null
        return $?
    elif command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | grep -qE "[:.]${port} "
        return $?
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -qE "[:.]${port} .*LISTEN"
        return $?
    fi
    return 2  # no probe tool — cannot determine
}

# Pick an available random port (returns port on stdout)
pick_available_port() {
    local port attempts=0 rv
    while [ $attempts -lt 20 ]; do
        if command -v shuf > /dev/null 2>&1; then
            port=$(shuf -i 10000-65000 -n 1)
        else
            port=$(( (RANDOM % 55000) + 10000 ))
        fi
        check_port_in_use "$port"; rv=$?
        if [ $rv -eq 1 ]; then
            echo "$port"
            return 0
        fi
        if [ $rv -eq 2 ]; then
            # No probe tool — accept the port; bind-time conflicts will surface
            # as a server startup error rather than silent flakiness.
            echo "$port"
            return 0
        fi
        attempts=$((attempts + 1))
    done
    return 1
}

# --- wolfSSL dependency resolution ---

find_wolfssl_options() {
    local base="$1"
    # Check both installed prefix (include/wolfssl/) and source tree (wolfssl/)
    if [ -f "$base/include/wolfssl/options.h" ]; then
        echo "$base/include/wolfssl/options.h"
    elif [ -f "$base/wolfssl/options.h" ]; then
        echo "$base/wolfssl/options.h"
    fi
}

check_wolfssl_options() {
    local base="$1"
    local opts_file
    opts_file=$(find_wolfssl_options "$base")
    [ -n "$opts_file" ] || return 1
    grep -q "^#define HAVE_PK_CALLBACKS" "$opts_file" && \
    grep -q "^#define WOLFSSL_KEY_GEN" "$opts_file" && \
    grep -q "^#define WOLFSSL_PUBLIC_MP" "$opts_file" && \
    grep -q "^#define WC_RSA_NO_PADDING" "$opts_file"
}

ensure_wolfssl() {
    local src

    # 1. Explicit WOLFSSL_PATH from environment
    if [ -n "$WOLFSSL_PATH" ] && check_wolfssl_options "$WOLFSSL_PATH"; then
        echo "  wolfSSL: using $WOLFSSL_PATH"
        return 0
    fi

    # 2. Reuse prior /tmp build
    src="/tmp/wolfssl-fwtpm"
    if [ -d "$src" ] && check_wolfssl_options "$src"; then
        WOLFSSL_PATH="$src"
        echo "  wolfSSL: using $WOLFSSL_PATH"
        return 0
    fi

    # 3. Check system install paths
    for src in /usr/local /usr /opt/homebrew /opt/local; do
        if check_wolfssl_options "$src"; then
            WOLFSSL_PATH="$src"
            echo "  wolfSSL: using system install at $WOLFSSL_PATH"
            return 0
        fi
    done

    echo "  wolfSSL not available with required options."
    echo "  Set WOLFSSL_PATH or install wolfSSL system-wide."
    echo "  Skipping TLS-dependent tests."
    return 1
}

# --- Cleanup ---

cleanup() {
    if [ "$STARTED_SERVER" = "1" ] && [ -f "$PID_FILE" ]; then
        local spid
        spid="$(cat "$PID_FILE")"
        kill "$spid" 2>/dev/null
        # SHM-mode server may block on sem_wait — force kill after 2s
        local i=0
        while kill -0 "$spid" 2>/dev/null && [ $i -lt 20 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        kill -9 "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
        rm -f "$PID_FILE"
        rm -f /tmp/fwtpm.shm
    fi
    rm -f /tmp/wolftpm_tls_ready_$$
}
trap cleanup EXIT

# --- Pre-flight checks ---

# Detect build options from wolftpm/options.h
IS_SWTPM_MODE=0
IS_FWTPM_MODE=0
HAS_GETENV=1
WOLFTPM_OPTIONS="$BUILD_DIR/wolftpm/options.h"
if [ -f "$WOLFTPM_OPTIONS" ]; then
    if grep -q "^#define WOLFTPM_SWTPM" "$WOLFTPM_OPTIONS"; then
        IS_SWTPM_MODE=1
    fi
    if grep -q "^#define WOLFTPM_FWTPM_BUILD" "$WOLFTPM_OPTIONS"; then
        IS_FWTPM_MODE=1
    fi
    if grep -q "^#define NO_GETENV" "$WOLFTPM_OPTIONS"; then
        HAS_GETENV=0
    fi
fi

# Determine mode
if [ $IS_FWTPM_MODE -eq 1 ]; then
    if [ ! -x "$FWTPM_SERVER" ]; then
        echo "fwtpm_server not built, skipping"
        exit 77
    fi
    if [ $IS_SWTPM_MODE -eq 1 ]; then
        echo "Mode: fwTPM + socket transport"
    else
        echo "Mode: fwTPM + TIS/SHM transport"
    fi
elif [ $IS_SWTPM_MODE -eq 1 ]; then
    echo "Mode: external TPM server (swtpm)"
else
    echo "No swtpm or fwtpm transport configured, skipping"
    exit 77
fi

# --- Resolve wolfSSL ---

echo "=== Resolving wolfSSL dependency ==="
if ! ensure_wolfssl; then
    echo "WARN: wolfSSL not available, TLS tests will be skipped"
    WOLFSSL_PATH=""
fi

# Check if the linked wolfSSL (system or WOLFSSL_PATH) has WC_RSA_NO_PADDING
# This is required for fwTPM RSA raw encrypt/decrypt operations
HAS_RSA_NO_PAD=0
for chk_path in "$WOLFSSL_PATH" "/usr/local"; do
    opts=$(find_wolfssl_options "$chk_path" 2>/dev/null)
    if [ -n "$opts" ] && grep -q "^#define WC_RSA_NO_PADDING" "$opts" 2>/dev/null; then
        HAS_RSA_NO_PAD=1
        break
    fi
done
if [ $HAS_RSA_NO_PAD -eq 0 ]; then
    echo "WARN: wolfSSL missing WC_RSA_NO_PADDING — skipping example tests"
    echo "      Rebuild wolfSSL with: CFLAGS=\"-DWC_RSA_NO_PADDING\""
    echo "      fwTPM requires WC_RSA_NO_PADDING for RSA encrypt/decrypt"
    SKIP_EXAMPLES=1
fi

# --- Auto-detect feature flags for run_examples.sh ---

# Defaults (match run_examples.sh defaults)
WOLFCRYPT_ENABLE=${WOLFCRYPT_ENABLE:-1}
WOLFCRYPT_RSA=${WOLFCRYPT_RSA:-1}
WOLFCRYPT_ECC=${WOLFCRYPT_ECC:-1}
NO_FILESYSTEM=${NO_FILESYSTEM:-0}
NO_PUBASPRIV=${NO_PUBASPRIV:-0}
WOLFCRYPT_DEFAULT=${WOLFCRYPT_DEFAULT:-0}

# Detect from wolftpm/options.h
if [ -f "$WOLFTPM_OPTIONS" ] && grep -q "^#define WOLFTPM2_NO_WOLFCRYPT" "$WOLFTPM_OPTIONS"; then
    WOLFCRYPT_ENABLE=0
fi

# Detect from wolfSSL options.h (system-installed or WOLFSSL_PATH)
WOLFSSL_OPTS=""
for chk in /usr/local "$WOLFSSL_PATH"; do
    [ -z "$chk" ] && continue
    found=$(find_wolfssl_options "$chk" 2>/dev/null)
    if [ -n "$found" ]; then WOLFSSL_OPTS="$found"; break; fi
done

if [ -n "$WOLFSSL_OPTS" ]; then
    grep -q "^#define NO_RSA" "$WOLFSSL_OPTS" && WOLFCRYPT_RSA=0
    grep -q "^#define HAVE_ECC" "$WOLFSSL_OPTS" || WOLFCRYPT_ECC=0
    grep -q "^#define NO_FILESYSTEM" "$WOLFSSL_OPTS" && NO_FILESYSTEM=1
    grep -q "^#define WOLFSSL_PUBLIC_ASN_PRIV_KEY" "$WOLFSSL_OPTS" || NO_PUBASPRIV=1
    grep -q "^#define WOLFSSL_AES_CFB" "$WOLFSSL_OPTS" || WOLFCRYPT_DEFAULT=1
fi

# --- Determine port and start/detect server ---

# Default port (honor env var override)
FWTPM_PORT="${TPM2_SWTPM_PORT:-2321}"
FWTPM_PLAT_PORT=$((FWTPM_PORT + 1))

if [ $IS_FWTPM_MODE -eq 1 ]; then
    # --- fwTPM mode: we manage the server lifecycle ---

    # Check if a server is already running (e.g. started by CI)
    if [ $IS_SWTPM_MODE -eq 1 ] && check_port_in_use "$FWTPM_PORT"; then
        echo "Server already running on port $FWTPM_PORT"
        if [ $HAS_GETENV -eq 1 ]; then
            export TPM2_SWTPM_PORT="$FWTPM_PORT"
        fi
    else
        # Clean stale artifacts and start our own server
        rm -f "$BUILD_DIR/fwtpm_nv.bin" /tmp/fwtpm.shm
        rm -f "$BUILD_DIR/rsa_test_blob.raw" "$BUILD_DIR/ecc_test_blob.raw" \
              "$BUILD_DIR/keyblob.bin"
        rm -f "$BUILD_DIR"/certs/tpm-*-cert.pem "$BUILD_DIR"/certs/tpm-*-cert.csr
        rm -f "$BUILD_DIR"/certs/server-*-cert.pem "$BUILD_DIR"/certs/client-*-cert.pem

        # Clean up any stale PID files from prior crashed runs.
        # Validate the process is actually fwtpm_server before killing —
        # PIDs can be reused, and signalling an unrelated process would
        # cause collateral damage.
        for stale_pid_file in /tmp/fwtpm_check_*.pid; do
            [ -f "$stale_pid_file" ] || continue
            stale_pid="$(cat "$stale_pid_file" 2>/dev/null)"
            if [ -n "$stale_pid" ] && kill -0 "$stale_pid" 2>/dev/null; then
                stale_comm="$(ps -p "$stale_pid" -o comm= 2>/dev/null)"
                case "$stale_comm" in
                    fwtpm_server|*fwtpm_server*)
                        kill "$stale_pid" 2>/dev/null
                        sleep 0.3
                        ;;
                esac
            fi
            rm -f "$stale_pid_file"
        done

        if [ $HAS_GETENV -eq 1 ] && [ $IS_SWTPM_MODE -eq 1 ]; then
            if [ "${FWTPM_USE_FIXED_PORT:-0}" != "1" ]; then
                FWTPM_PORT=$(pick_available_port)
                if [ -z "$FWTPM_PORT" ]; then
                    echo "FAIL: Could not find available port"
                    exit 1
                fi
            else
                echo "Using fixed port $FWTPM_PORT (namespace isolation)"
            fi
            FWTPM_PLAT_PORT=$((FWTPM_PORT + 1))
            export TPM2_SWTPM_PORT="$FWTPM_PORT"
        fi

        STARTED_SERVER=1
        if [ $IS_SWTPM_MODE -eq 1 ]; then
            "$FWTPM_SERVER" --port "$FWTPM_PORT" --platform-port "$FWTPM_PLAT_PORT" \
                > /tmp/fwtpm_check_$$.log 2>&1 &
        else
            "$FWTPM_SERVER" > /tmp/fwtpm_check_$$.log 2>&1 &
        fi
        echo $! > "$PID_FILE"

        if [ $IS_SWTPM_MODE -eq 1 ]; then
            if ! wait_for_port "$FWTPM_PORT" 500; then
                echo "FAIL: fwtpm_server failed to start on port $FWTPM_PORT"
                cat /tmp/fwtpm_check_$$.log
                exit 1
            fi
            echo "fwTPM server started (pid=$(cat "$PID_FILE"), port=$FWTPM_PORT)"
        else
            # TIS/SHM mode: wait for shared memory file
            elapsed=0
            while [ ! -f /tmp/fwtpm.shm ] && [ $elapsed -lt 500 ]; do
                sleep 0.01
                elapsed=$((elapsed + 1))
            done
            if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
                echo "FAIL: fwtpm_server failed to start"
                cat /tmp/fwtpm_check_$$.log
                exit 1
            fi
            echo "fwTPM server started (pid=$(cat "$PID_FILE"), transport=SHM)"
        fi
    fi
else
    # --- swtpm-only mode: detect existing external TPM server ---

    if [ $HAS_GETENV -eq 1 ]; then
        export TPM2_SWTPM_PORT="$FWTPM_PORT"
    fi

    if ! check_port_in_use "$FWTPM_PORT"; then
        echo "No TPM server on port $FWTPM_PORT, skipping (start one with: tpm_server &)"
        exit 77
    fi
    echo "Using external TPM server on port $FWTPM_PORT"

    # Clean stale artifacts (NV state belongs to external server, don't touch it)
    rm -f "$BUILD_DIR/rsa_test_blob.raw" "$BUILD_DIR/ecc_test_blob.raw" \
          "$BUILD_DIR/keyblob.bin"
    rm -f "$BUILD_DIR"/certs/tpm-*-cert.pem "$BUILD_DIR"/certs/tpm-*-cert.csr
    rm -f "$BUILD_DIR"/certs/server-*-cert.pem "$BUILD_DIR"/certs/client-*-cert.pem
fi

# --- Run unit tests ---

if [ -x "$UNIT_TEST" ]; then
    echo ""
    echo "=== Running unit.test ==="
    cd "$BUILD_DIR"
    if TPM2_SWTPM_PORT="$FWTPM_PORT" "$UNIT_TEST"; then
        PASS=$((PASS + 1))
        echo "PASS: unit.test"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: unit.test"
    fi
else
    echo "SKIP: unit.test not found"
    SKIP=$((SKIP + 1))
fi

# --- Run examples ---

if [ $SKIP_EXAMPLES -eq 1 ]; then
    echo "SKIP: run_examples.sh (missing WC_RSA_NO_PADDING)"
    SKIP=$((SKIP + 1))
elif [ -x "$RUN_EXAMPLES" ]; then
    echo ""
    echo "=== Running run_examples.sh ==="
    cd "$BUILD_DIR"
    if WOLFSSL_PATH="$WOLFSSL_PATH" TPM2_SWTPM_PORT="$FWTPM_PORT" \
        WOLFCRYPT_ENABLE="$WOLFCRYPT_ENABLE" \
        WOLFCRYPT_RSA="$WOLFCRYPT_RSA" \
        WOLFCRYPT_ECC="$WOLFCRYPT_ECC" \
        NO_FILESYSTEM="$NO_FILESYSTEM" \
        NO_PUBASPRIV="$NO_PUBASPRIV" \
        WOLFCRYPT_DEFAULT="$WOLFCRYPT_DEFAULT" \
        "$RUN_EXAMPLES"; then
        PASS=$((PASS + 1))
        echo "PASS: run_examples.sh"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: run_examples.sh"
    fi
else
    echo "SKIP: run_examples.sh not found"
    SKIP=$((SKIP + 1))
fi

# --- Run tpm2-tools tests if available ---

# tpm2-tools speaks TCP TCTI (mssim/swtpm) only — TIS/SHM-only builds have no
# socket and must skip. Otherwise reuse our fwtpm_server on $FWTPM_PORT and
# call the script with --no-start. The script honors TPM2_SWTPM_PORT.
TPM2_TOOLS_SCRIPT="$SRC_DIR/scripts/tpm2_tools_test.sh"
if [ $IS_SWTPM_MODE -ne 1 ]; then
    echo "SKIP: tpm2-tools (requires --enable-swtpm for TCP socket transport)"
    SKIP=$((SKIP + 1))
elif [ -x "$TPM2_TOOLS_SCRIPT" ]; then
    echo ""
    echo "=== Running tpm2_tools_test.sh ==="
    cd "$BUILD_DIR"

    # Restart fwtpm_server with a clean NV file so the tpm2-tools tests get
    # isolated state. tpm2_clear is not enough — example NV indices created
    # in run_examples.sh (e.g. 0x1500001) are not always cleared by it.
    # Only restart if we actually started the server ourselves.
    if [ $STARTED_SERVER -eq 1 ]; then
        if [ -f "$PID_FILE" ]; then
            kill "$(cat "$PID_FILE")" 2>/dev/null || true
            sleep 0.3
        fi
        rm -f "$BUILD_DIR/fwtpm_nv.bin"
        echo "--- fwtpm_server restart for tpm2-tools ---" \
            >> /tmp/fwtpm_check_$$.log
        "$FWTPM_SERVER" --port "$FWTPM_PORT" \
            --platform-port "$FWTPM_PLAT_PORT" \
            >> /tmp/fwtpm_check_$$.log 2>&1 &
        echo $! > "$PID_FILE"
        if ! wait_for_port "$FWTPM_PORT" 500; then
            echo "FAIL: fwtpm_server restart failed before tpm2-tools tests"
            cat /tmp/fwtpm_check_$$.log
            FAIL=$((FAIL + 1))
            echo ""
            echo "=== fwTPM Integration Results: $PASS passed, $FAIL failed, $SKIP skipped ==="
            exit 1
        fi
    fi

    TPM2_SWTPM_PORT="$FWTPM_PORT" "$TPM2_TOOLS_SCRIPT" --no-start
    rc=$?
    if [ $rc -eq 0 ]; then
        PASS=$((PASS + 1))
        echo "PASS: tpm2_tools_test.sh"
    elif [ $rc -eq 77 ]; then
        SKIP=$((SKIP + 1))
        echo "SKIP: tpm2_tools_test.sh (tpm2-tools not installed)"
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: tpm2_tools_test.sh (exit $rc)"
    fi
else
    echo "SKIP: tpm2_tools_test.sh not found"
    SKIP=$((SKIP + 1))
fi

echo ""
echo "=== fwTPM Integration Results: $PASS passed, $FAIL failed, $SKIP skipped ==="

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
