#!/bin/bash
# End-to-end harness: spawn fwtpm_server, run examples/pqc/pqc_mssim_e2e
# client against it over the mssim socket, assert success, clean up.
#
# Proves the client marshaling + mssim framing + fwtpm_server dispatch
# + PQC handlers agree over a real TCP socket — orthogonal to the
# in-process fwtpm_unit.test suite.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

SERVER="$REPO_ROOT/src/fwtpm/fwtpm_server"
CLIENT="$REPO_ROOT/examples/pqc/pqc_mssim_e2e"
NV_FILE="$REPO_ROOT/fwtpm_mssim_e2e_nv.bin"
PORT=2321
PLATFORM_PORT=2322

# Pre-flight checks.
if [ ! -x "$SERVER" ]; then
    echo "SKIP: fwtpm_server not built — configure with --enable-v185" >&2
    exit 77
fi
if [ ! -x "$CLIENT" ]; then
    echo "SKIP: pqc_mssim_e2e not built — configure with --enable-swtpm --enable-v185" >&2
    exit 77
fi

# Kill any stale server on our port before we start.
pkill -f "fwtpm_server.*--port $PORT" 2>/dev/null || true
sleep 1
rm -f "$NV_FILE"

echo "== Starting fwtpm_server on port $PORT =="
FWTPM_NV_FILE="$NV_FILE" "$SERVER" \
    --port $PORT --platform-port $PLATFORM_PORT --clear \
    >"$SCRIPT_DIR/fwtpm_server.log" 2>&1 &
SERVER_PID=$!

# Wait up to 5s for the server to accept TCP connections. /dev/tcp prints
# "Connection refused" to stderr on each miss; redirect the whole subshell
# so we only surface the final outcome.
(
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if exec 3<>/dev/tcp/127.0.0.1/$PORT; then
            exec 3>&-
            exit 0
        fi
        sleep 0.5
    done
    exit 1
) 2>/dev/null
probe_rc=$?

if [ $probe_rc -ne 0 ] || ! kill -0 "$SERVER_PID" 2>/dev/null; then
    echo "FAIL: fwtpm_server not accepting connections on port $PORT" >&2
    tail -20 "$SCRIPT_DIR/fwtpm_server.log" >&2
    kill "$SERVER_PID" 2>/dev/null || true
    rm -f "$NV_FILE"
    exit 1
fi

echo "== Running PQC mssim E2E client =="
"$CLIENT"
RC=$?

echo "== Stopping fwtpm_server (pid $SERVER_PID) =="
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null
rm -f "$NV_FILE"

if [ $RC -eq 0 ]; then
    echo "OK: PQC mssim E2E passed"
    exit 0
else
    echo "FAIL: PQC mssim E2E client exited with rc=$RC" >&2
    tail -30 "$SCRIPT_DIR/fwtpm_server.log" >&2
    exit $RC
fi
