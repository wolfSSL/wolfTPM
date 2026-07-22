#!/bin/bash
# tls_pq_e2e.sh
#
# Copyright (C) 2006-2026 wolfSSL Inc.
#
# This file is part of wolfTPM.
#
# wolfTPM is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfTPM is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#

# End-to-end harness for the post-quantum TLS example: spawn fwtpm_server,
# generate a TPM-keyed ML-DSA cert chain, run tls_server_pq and tls_client_pq
# over a real TCP socket, and assert the full PQC handshake (ML-KEM key
# exchange + TPM-signed ML-DSA authentication, CA-verified) plus app data.

set -u

# returns: 0 = in use, 1 = free, 2 = no probe tool
check_port_in_use() {
    if command -v nc >/dev/null 2>&1; then
        nc -z localhost "$1" 2>/dev/null; return $?
    elif command -v ss >/dev/null 2>&1; then
        ss -tln 2>/dev/null | grep -qE "[:.]$1 "; return $?
    elif command -v netstat >/dev/null 2>&1; then
        netstat -an 2>/dev/null | grep -qE "[:.]$1 .*LISTEN"; return $?
    fi
    return 2
}

pick_available_port() {
    local port attempts=0
    while [ $attempts -lt 20 ]; do
        if command -v shuf >/dev/null 2>&1; then port=$(shuf -i 10000-60000 -n 1)
        else port=$(( (RANDOM % 50000) + 10000 )); fi
        check_port_in_use "$port"; [ $? -ne 0 ] && { echo "$port"; return 0; }
        attempts=$((attempts + 1))
    done
    return 1
}

# pick a port whose consecutive platform port (port+1) is also free
pick_available_pair() {
    local port attempts=0
    while [ $attempts -lt 20 ]; do
        port=$(pick_available_port) || return 1
        check_port_in_use "$((port + 1))" || { echo "$port"; return 0; }
        attempts=$((attempts + 1))
    done
    return 1
}

# wait for $1 to reach LISTEN (ss/netstat, not nc -z which eats the accept slot)
wait_for_listen() {
    local port="$1" pid="$2" elapsed=0
    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        sleep 2; return 0
    fi
    while [ $elapsed -lt 400 ]; do
        kill -0 "$pid" 2>/dev/null || return 1
        if command -v ss >/dev/null 2>&1; then
            ss -tln 2>/dev/null | grep -qE "[:.]${port} " && return 0
        elif netstat -an 2>/dev/null | grep -qE "[:.]${port} .*LISTEN"; then
            return 0
        fi
        sleep 0.02
        elapsed=$((elapsed + 1))
    done
    return 1
}

# binaries and generated artifacts live in the build tree (VPATH-safe)
BUILD_DIR="$(pwd)"
cd "$BUILD_DIR" || exit 1

SERVER="$BUILD_DIR/src/fwtpm/fwtpm_server"
GEN="$BUILD_DIR/examples/pqc/gen_pqc_certs"
TLS_SRV="$BUILD_DIR/examples/tls/tls_server_pq"
TLS_CLI="$BUILD_DIR/examples/tls/tls_client_pq"
# fwTPM uses the compile-time FWTPM_NV_FILE (cwd-relative), not an env var
NV_FILE="$BUILD_DIR/fwtpm_nv.bin"
LOGP="/tmp/tls_pq_e2e_$$"
# examples honor TPM2_SWTPM_PORT only when built with getenv support
HAS_GETENV=1
WOLFTPM_OPTS="$BUILD_DIR/wolftpm/options.h"
if [ -f "$WOLFTPM_OPTS" ] && grep -q "^#define NO_GETENV" "$WOLFTPM_OPTS"; then
    HAS_GETENV=0
fi
PORT="${TPM2_SWTPM_PORT:-2321}"
if check_port_in_use "$PORT" || check_port_in_use "$((PORT + 1))"; then
    if [ "$HAS_GETENV" -eq 1 ]; then
        PORT="$(pick_available_pair)"
    else
        echo "SKIP: TPM ports $PORT/$((PORT + 1)) busy (NO_GETENV build)" >&2
        exit 77
    fi
fi
PLATFORM_PORT=$((PORT + 1))
TLS_PORT="$(pick_available_port)"
port_tries=0
while { [ "$TLS_PORT" = "$PORT" ] || [ "$TLS_PORT" = "$PLATFORM_PORT" ]; } \
        && [ $port_tries -lt 10 ]; do
    TLS_PORT="$(pick_available_port)"
    port_tries=$((port_tries + 1))
done
GROUP="${1:-ML_KEM_768}"
MLDSA="${2:-65}"
if [ -z "$PORT" ] || [ -z "$TLS_PORT" ]; then
    echo "SKIP: could not allocate a free port" >&2; exit 77
fi

for bin in "$SERVER" "$GEN" "$TLS_SRV" "$TLS_CLI"; do
    if [ ! -x "$bin" ]; then
        echo "SKIP: $(basename "$bin") not built — configure --enable-fwtpm --enable-swtpm --enable-pqc" >&2
        exit 77
    fi
done

# the examples compile executable stubs when wolfSSL cert-gen / private-key-id /
# TLS 1.3 support is missing; skip rather than fail in that build matrix
for bin in "$GEN" "$TLS_SRV" "$TLS_CLI"; do
    if "$bin" -h 2>&1 | grep -q "Requires"; then
        echo "SKIP: $(basename "$bin") built without required wolfSSL features" >&2
        exit 77
    fi
done

export TPM2_SWTPM_PORT=$PORT

rm -f "$NV_FILE"

echo "== Starting fwtpm_server on port $PORT =="
"$SERVER" \
    --port $PORT --platform-port $PLATFORM_PORT --clear \
    >"${LOGP}_fwtpm.log" 2>&1 &
SERVER_PID=$!

(
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if exec 3<>/dev/tcp/127.0.0.1/$PORT; then exec 3>&-; exit 0; fi
        sleep 0.5
    done
    exit 1
) 2>/dev/null
if [ $? -ne 0 ] || ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: fwtpm_server not accepting connections on port $PORT" >&2
    kill "$SERVER_PID" 2>/dev/null; rm -f "$NV_FILE"; exit 1
fi

TLS_SRV_PID=""
cleanup() {
    [ -n "$TLS_SRV_PID" ] && kill "$TLS_SRV_PID" 2>/dev/null
    TLS_SRV_PID=""
    [ -n "$SERVER_PID" ] && { kill "$SERVER_PID" 2>/dev/null; \
        wait "$SERVER_PID" 2>/dev/null; }
    SERVER_PID=""
    rm -f "$NV_FILE" "$BUILD_DIR/certs/pq-ca-cert.der" \
        "$BUILD_DIR/certs/pq-server-cert.der"
}
trap cleanup EXIT

mkdir -p "$BUILD_DIR/certs"
echo "== Generating TPM ML-DSA-$MLDSA cert chain =="
if ! "$GEN" -mldsa=$MLDSA >"${LOGP}_gen.log" 2>&1; then
    echo "FAIL: gen_pqc_certs" >&2; cat "${LOGP}_gen.log" >&2; cleanup; exit 1
fi

echo "== Starting tls_server_pq on port $TLS_PORT =="
"$TLS_SRV" -p=$TLS_PORT -mldsa=$MLDSA >"${LOGP}_server.log" 2>&1 &
TLS_SRV_PID=$!
if ! wait_for_listen "$TLS_PORT" "$TLS_SRV_PID"; then
    echo "FAIL: tls_server_pq not listening on port $TLS_PORT" >&2
    cat "${LOGP}_server.log" >&2; cleanup; exit 1
fi

echo "== Running tls_client_pq (group $GROUP) =="
"$TLS_CLI" -h=localhost -p=$TLS_PORT -group=$GROUP >"${LOGP}_client.log" 2>&1
CLI_RC=$?

# if the client connected, the server serves it and exits; wait to flush its
# log. Otherwise (e.g. unsupported group) kill it so we do not hang forever.
if [ $CLI_RC -eq 0 ]; then
    wait "$TLS_SRV_PID" 2>/dev/null
else
    kill "$TLS_SRV_PID" 2>/dev/null
fi
TLS_SRV_PID=""

cleanup

CLI=$(cat "${LOGP}_client.log")
SRV=$(cat "${LOGP}_server.log")
FAIL=0
echo "$CLI" | grep -qi "group $GROUP"           || { echo "FAIL: client did not negotiate $GROUP" >&2; FAIL=1; }
echo "$CLI" | grep -q "verified against the CA" || { echo "FAIL: client did not verify server cert" >&2; FAIL=1; }
echo "$CLI" | grep -q "I hear you fa shizzle"   || { echo "FAIL: no app data from server" >&2; FAIL=1; }
echo "$SRV" | grep -q "signed on TPM"           || { echo "FAIL: server did not sign on the TPM" >&2; FAIL=1; }

if [ $CLI_RC -eq 0 ] && [ $FAIL -eq 0 ]; then
    echo "OK: PQC TLS handshake (ML-KEM $GROUP + TPM ML-DSA-$MLDSA) passed"
    exit 0
fi
echo "FAIL: PQC TLS E2E (client rc=$CLI_RC)" >&2
if ! echo "$SRV" | grep -q "signed on TPM"; then
    echo "HINT: server never signed on the TPM — the linked wolfSSL may lack the" >&2
    echo "      wc_MlDsaKey_SignCtx crypto-callback route (see examples/pqc/README.md)" >&2
fi
echo "--- client ---" >&2; echo "$CLI" >&2
echo "--- server ---" >&2; echo "$SRV" >&2
exit 1
