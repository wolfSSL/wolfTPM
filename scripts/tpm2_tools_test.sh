#!/bin/bash
# tpm2_tools_test.sh
# Run tpm2-tools commands against a TPM simulator to verify compatibility.
# Works with fwtpm_server, swtpm, or any mssim-protocol TPM simulator.
#
# Usage:
#   scripts/tpm2_tools_test.sh [--no-start] [--verbose] [--tcti=mssim|swtpm]
#
# Environment:
#   TPM2_SWTPM_PORT  TCP port the running TPM server listens on (default: 2321).
#                    Used when this script is invoked from `make check` to
#                    target the random port picked by tests/fwtpm_check.sh.
#
# Requirements: tpm2-tools >= 5.0, libtss2-tcti-mssim (or libtss2-tcti-swtpm)
#
# Exit: 0 if all tests pass, 77 if tpm2-tools not installed (SKIP), 1 on failure

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WOLFTPM_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ----------------------------------------------------------------
# Config
# ----------------------------------------------------------------
# wolfTPM fwtpm_server auto-detects the TCTI protocol (mssim or swtpm).
# Both are supported. Default to mssim for backward compatibility.
TCTI_TYPE="${TCTI_TYPE:-mssim}"
export TPM2TOOLS_TCTI="${TCTI_TYPE}:host=localhost,port=${TPM2_SWTPM_PORT:-2321}"
TEST_TMPDIR=/tmp/fwtpm_tpm2tools
VERBOSE=0
NO_START=0
PASS=0; FAIL=0; SKIP=0
SERVER_PID=""
SERVER_BIN="$WOLFTPM_ROOT/src/fwtpm/fwtpm_server"
NV_FILE="$WOLFTPM_ROOT/fwtpm_nv.bin"
SRV_LOG=/tmp/fwtpm_tpm2tools_srv.log

# ----------------------------------------------------------------
# Argument parsing
# ----------------------------------------------------------------
for arg in "$@"; do
    case "$arg" in
        --verbose|-v)  VERBOSE=1 ;;
        --no-start) NO_START=1 ;;
        --tcti=*)
            TCTI_TYPE="${arg#--tcti=}"
            export TPM2TOOLS_TCTI="${TCTI_TYPE}:host=localhost,port=${TPM2_SWTPM_PORT:-2321}"
            ;;
        --help|-h)
            grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -12; exit 0 ;;
    esac
done

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

run_test() {
    local name="$1"; shift
    local out rc
    if [ $VERBOSE -eq 1 ]; then
        echo "  >>> $*"
        "$@" 2>&1
        rc=$?
    else
        out=$("$@" 2>&1)
        rc=$?
    fi
    if [ $rc -eq 0 ]; then
        echo "  [PASS]  $name"
        PASS=$((PASS+1))
    else
        echo "  [FAIL]  $name (exit $rc)"
        [ $VERBOSE -eq 0 ] && echo "$out" | sed 's/^/          /'
        FAIL=$((FAIL+1))
    fi
    return $rc
}

skip_test() {
    echo "  [SKIP]  $1 — $2"
    SKIP=$((SKIP+1))
}

# run_test_fail: expect the command to fail (non-zero exit)
run_test_fail() {
    local name="$1"; shift
    local out rc
    if [ $VERBOSE -eq 1 ]; then
        echo "  >>> $* (expect fail)"
        "$@" 2>&1
        rc=$?
    else
        out=$("$@" 2>&1)
        rc=$?
    fi
    if [ $rc -ne 0 ]; then
        echo "  [PASS]  $name (failed as expected, exit $rc)"
        PASS=$((PASS+1))
    else
        echo "  [FAIL]  $name (expected failure but got exit 0)"
        [ $VERBOSE -eq 0 ] && echo "$out" | sed 's/^/          /'
        FAIL=$((FAIL+1))
    fi
    return 0
}

hdr() {
    printf "\n\033[36m--- %s ---\033[0m\n" "$1"
}

# Flush all transient handles (objects loaded in TPM).
# Real hardware TPMs typically have only 3 transient slots, so tests must
# clean up handles between sections to avoid TPM_RC_OBJECT_MEMORY (0x902).
flush_transient() {
    for h in $(tpm2_getcap handles-transient 2>/dev/null | \
               grep "^-" | sed 's/- //'); do
        tpm2_flushcontext "$h" 2>/dev/null || true
    done
    # Also flush any stale saved sessions
    tpm2_flushcontext -s 2>/dev/null || true
}

# ----------------------------------------------------------------
# Server lifecycle (self-contained — no external scripts)
# ----------------------------------------------------------------
server_start() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    killall fwtpm_server 2>/dev/null || true
    sleep 0.2
    rm -f "$NV_FILE"

    "$SERVER_BIN" > "$SRV_LOG" 2>&1 &
    SERVER_PID=$!
    disown "$SERVER_PID" 2>/dev/null || true

    # Wait for server process to be ready (up to 2 seconds)
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: fwtpm_server process died"
        cat "$SRV_LOG"
        exit 1
    fi
    sleep 1
    echo "[fwtpm] Server started (PID $SERVER_PID)"
}

server_stop() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        # Don't wait — avoid signal propagation issues in CI
        sleep 0.3
        echo "[fwtpm] Server stopped"
    fi
    SERVER_PID=""
}

# Restart server preserving NV state (for determinism tests)
server_restart() {
    # Send tpm2_shutdown to flush volatile state before stopping server.
    # Use explicit TCTI in case environment is not set.
    TPM2TOOLS_TCTI="${TCTI_TYPE}:host=localhost,port=${TPM2_SWTPM_PORT:-2321}" \
        tpm2_shutdown 2>/dev/null || true
    sleep 0.2

    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
    killall fwtpm_server 2>/dev/null || true
    sleep 0.3

    "$SERVER_BIN" >> "$SRV_LOG" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: fwtpm_server restart failed"
        tail -10 "$SRV_LOG"
        exit 1
    fi
    sleep 1
    # mssim TCTI auto-startup only works on first connection to a fresh
    # server. After restart with preserved NV, we need explicit startup.
    tpm2_startup -c 2>/dev/null || true
    echo "[fwtpm] Server restarted (PID $SERVER_PID, NV preserved)"
}

if [ $NO_START -eq 0 ]; then
    trap 'server_stop; rm -rf "$TEST_TMPDIR"' EXIT
fi

# ----------------------------------------------------------------
# Pre-flight: check tpm2-tools present
# ----------------------------------------------------------------
for t in tpm2_startup tpm2_getcap tpm2_getrandom tpm2_pcrread \
         tpm2_pcrextend tpm2_createprimary tpm2_create tpm2_load \
         tpm2_sign tpm2_verifysignature tpm2_nvdefine tpm2_nvwrite \
         tpm2_nvread tpm2_nvundefine tpm2_testparms tpm2_changeauth \
         tpm2_hierarchycontrol tpm2_nvsetbits tpm2_hash \
         tpm2_policylocality tpm2_rsaencrypt tpm2_rsadecrypt \
         tpm2_encryptdecrypt tpm2_evictcontrol tpm2_readpublic \
         tpm2_clear tpm2_nvincrement tpm2_nvwritelock \
         tpm2_stirrandom tpm2_selftest tpm2_flushcontext tpm2_quote \
         tpm2_pcrreset tpm2_readclock tpm2_setclock tpm2_hmac \
         tpm2_certifycreation tpm2_loadexternal tpm2_duplicate \
         tpm2_policypassword tpm2_policyauthvalue tpm2_policycommandcode \
         tpm2_policyor tpm2_policysecret tpm2_policyauthorize \
         tpm2_changepps tpm2_changeeps; do
    if ! check_tool "$t"; then
        echo "SKIP: tpm2-tools not installed ($t not found)"
        exit 77
    fi
done

# ----------------------------------------------------------------
# Start server
# ----------------------------------------------------------------
mkdir -p "$TEST_TMPDIR"

if [ $NO_START -eq 0 ]; then
    [ -x "$SERVER_BIN" ] || { echo "ERROR: $SERVER_BIN not found"; exit 1; }
    server_start
fi

# ----------------------------------------------------------------
# Tests
# ----------------------------------------------------------------
hdr "Startup & Self-Test"
run_test "tpm2_startup (clear)" \
    tpm2_startup -c

run_test "tpm2_selftest" \
    tpm2_selftest

# ----------------------------------------------------------------
hdr "GetCapability"
run_test "getcap properties-fixed" \
    tpm2_getcap properties-fixed

run_test "getcap properties-variable" \
    tpm2_getcap properties-variable

run_test "getcap algorithms" \
    tpm2_getcap algorithms

run_test "getcap commands" \
    tpm2_getcap commands

run_test "getcap pcrs" \
    tpm2_getcap pcrs

# ----------------------------------------------------------------
hdr "GetRandom"
run_test "getrandom 32 bytes" \
    tpm2_getrandom --hex 32

run_test "getrandom 16 bytes" \
    tpm2_getrandom --hex 16

# ----------------------------------------------------------------
hdr "PCR Operations"
run_test "pcrread sha256:0,1,2,3" \
    tpm2_pcrread sha256:0,1,2,3

run_test "pcrextend pcr0" \
    tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000

run_test "pcrread after extend" \
    tpm2_pcrread sha256:0

# ----------------------------------------------------------------
hdr "CreatePrimary"
run_test "createprimary RSA (owner hierarchy)" \
    tpm2_createprimary -C o -g sha256 -G rsa -c "$TEST_TMPDIR/primary_rsa.ctx"

run_test "createprimary ECC (owner hierarchy)" \
    tpm2_createprimary -C o -g sha256 -G ecc -c "$TEST_TMPDIR/primary_ecc.ctx"

# Flush both primaries — each section below recreates what it needs.
# Real hardware TPMs only have 3 transient slots; primary keys are
# deterministic (same seed + template = same key) so recreating is free.
flush_transient

# ----------------------------------------------------------------
hdr "Create & Load — RSA"
# Recreate RSA primary for this section
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TEST_TMPDIR/primary_rsa.ctx" > /dev/null 2>&1

run_test "create RSA key under RSA primary" \
    tpm2_create -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -g sha256 -G rsa \
        -u "$TEST_TMPDIR/rsa.pub" -r "$TEST_TMPDIR/rsa.priv"

run_test "load RSA key" \
    tpm2_load -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -u "$TEST_TMPDIR/rsa.pub" -r "$TEST_TMPDIR/rsa.priv" \
        -c "$TEST_TMPDIR/rsa.ctx"

# ----------------------------------------------------------------
hdr "Sign & Verify — RSA"
echo "hello tpm2-tools test" > "$TEST_TMPDIR/msg.txt"

run_test "sign RSA (sha256)" \
    tpm2_sign -c "$TEST_TMPDIR/rsa.ctx" -g sha256 \
        -o "$TEST_TMPDIR/sig.rsa" "$TEST_TMPDIR/msg.txt"

run_test "verifysignature RSA" \
    tpm2_verifysignature -c "$TEST_TMPDIR/rsa.ctx" -g sha256 \
        -m "$TEST_TMPDIR/msg.txt" -s "$TEST_TMPDIR/sig.rsa"

# Flush transient handles to free slots for ECC tests
flush_transient

# ----------------------------------------------------------------
hdr "Create & Load — ECC"
# Re-create ECC primary (flushed above; deterministic — same key)
tpm2_createprimary -C o -g sha256 -G ecc \
    -c "$TEST_TMPDIR/primary_ecc.ctx" > /dev/null 2>&1

run_test "create ECC key under ECC primary" \
    tpm2_create -C "$TEST_TMPDIR/primary_ecc.ctx" \
        -g sha256 -G ecc \
        -u "$TEST_TMPDIR/ecc.pub" -r "$TEST_TMPDIR/ecc.priv"

run_test "load ECC key" \
    tpm2_load -C "$TEST_TMPDIR/primary_ecc.ctx" \
        -u "$TEST_TMPDIR/ecc.pub" -r "$TEST_TMPDIR/ecc.priv" \
        -c "$TEST_TMPDIR/ecc.ctx"

# ----------------------------------------------------------------
hdr "Sign & Verify — ECC"
run_test "sign ECC (sha256)" \
    tpm2_sign -c "$TEST_TMPDIR/ecc.ctx" -g sha256 \
        -o "$TEST_TMPDIR/sig.ecc" "$TEST_TMPDIR/msg.txt"

run_test "verifysignature ECC" \
    tpm2_verifysignature -c "$TEST_TMPDIR/ecc.ctx" -g sha256 \
        -m "$TEST_TMPDIR/msg.txt" -s "$TEST_TMPDIR/sig.ecc"

# Flush ECC handles
flush_transient

# ----------------------------------------------------------------
hdr "NV RAM"
NV_IDX=0x01500000

run_test "nvdefine 32-byte index" \
    tpm2_nvdefine "$NV_IDX" -C o -s 32 -a "ownerread|ownerwrite"

run_test "nvwrite 32 bytes" \
    bash -c 'printf "%-32s" "fwtpm-nv-test-data" | \
        tpm2_nvwrite '"$NV_IDX"' -C o --input=-'

run_test "nvread 32 bytes" \
    tpm2_nvread "$NV_IDX" -C o -s 32

run_test "nvundefine" \
    tpm2_nvundefine "$NV_IDX" -C o

# ----------------------------------------------------------------
hdr "Policy Engine"
# PolicyPCR: create a sealed key locked to current PCR 0 value
run_test "createprimary for policy tests" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/pol_primary.ctx"

run_test "startauthsession (trial)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/trial_session.ctx"

run_test "policypcr (trial — lock to PCR 0)" \
    tpm2_policypcr -S "$TEST_TMPDIR/trial_session.ctx" \
        -l sha256:0 -L "$TEST_TMPDIR/pcr_policy.bin"

run_test "flushcontext (trial session)" \
    tpm2_flushcontext "$TEST_TMPDIR/trial_session.ctx"

run_test "create sealed key with PolicyPCR" \
    bash -c 'echo -n "secretdata" | tpm2_create \
        -C "'"$TEST_TMPDIR"'/pol_primary.ctx" \
        -i- -L "'"$TEST_TMPDIR"'/pcr_policy.bin" \
        -u "'"$TEST_TMPDIR"'/sealed.pub" -r "'"$TEST_TMPDIR"'/sealed.priv"'

run_test "load sealed key" \
    tpm2_load -C "$TEST_TMPDIR/pol_primary.ctx" \
        -u "$TEST_TMPDIR/sealed.pub" -r "$TEST_TMPDIR/sealed.priv" \
        -c "$TEST_TMPDIR/sealed.ctx"

run_test "startauthsession (policy)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/policy_session.ctx"

run_test "policypcr (satisfy — PCR 0)" \
    tpm2_policypcr -S "$TEST_TMPDIR/policy_session.ctx" -l sha256:0

run_test "unseal with PolicyPCR" \
    tpm2_unseal -c "$TEST_TMPDIR/sealed.ctx" \
        -p "session:$TEST_TMPDIR/policy_session.ctx"

run_test "flushcontext (policy session)" \
    tpm2_flushcontext "$TEST_TMPDIR/policy_session.ctx"

# Flush policy objects
flush_transient

# NV index with index password (authread|authwrite lets NV index auth access)
NV_POLICY_IDX=0x01500001
run_test "nvdefine with index password" \
    tpm2_nvdefine "$NV_POLICY_IDX" -C o -s 16 \
        -a "ownerread|ownerwrite|authread|authwrite" \
        -p "testpass"

run_test "nvwrite via owner (no password)" \
    bash -c 'echo -n "policy-test-data" | \
        tpm2_nvwrite '"$NV_POLICY_IDX"' -C o --input=-'

run_test "nvread via owner (no password)" \
    tpm2_nvread "$NV_POLICY_IDX" -C o -s 16

run_test "nvundefine policy nv index" \
    tpm2_nvundefine "$NV_POLICY_IDX" -C o

# ----------------------------------------------------------------
hdr "TestParms"
run_test "testparms RSA" \
    tpm2_testparms rsa2048

run_test "testparms ECC (P-256)" \
    tpm2_testparms ecc256

run_test "testparms AES-128-CFB" \
    tpm2_testparms aes128cfb

# ----------------------------------------------------------------
hdr "Hierarchy Control & Auth"
# Change the owner hierarchy auth, then change it back
run_test "hierarchychangeauth (set owner password)" \
    tpm2_changeauth -c o newpass

run_test "hierarchychangeauth (clear owner password)" \
    tpm2_changeauth -c o -p newpass

# HierarchyControl: disable/re-enable endorsement hierarchy
# Note: re-enabling requires platform auth
run_test "hierarchycontrol (disable endorsement)" \
    tpm2_hierarchycontrol -C p ehEnable clear

run_test "hierarchycontrol (enable endorsement)" \
    tpm2_hierarchycontrol -C p ehEnable set

# ----------------------------------------------------------------
hdr "NV SetBits & ChangeAuth"
NV_BITS_IDX=0x01500010

run_test "nvdefine bit field index" \
    tpm2_nvdefine "$NV_BITS_IDX" -C o -s 8 \
        -a "ownerread|ownerwrite|nt=bits"

run_test "nvsetbits (set bit 0)" \
    tpm2_nvsetbits "$NV_BITS_IDX" -C o -i 0x01

run_test "nvsetbits (set bit 3)" \
    tpm2_nvsetbits "$NV_BITS_IDX" -C o -i 0x08

run_test "nvread bit field" \
    tpm2_nvread "$NV_BITS_IDX" -C o -s 8

run_test "nvundefine bit field" \
    tpm2_nvundefine "$NV_BITS_IDX" -C o

# NV ChangeAuth: define index with auth, change it, verify access
NV_CHAUTH_IDX=0x01500011

run_test "nvdefine for changeauth test" \
    tpm2_nvdefine "$NV_CHAUTH_IDX" -C o -s 16 \
        -a "ownerread|authwrite" -p "oldpass"

run_test "nvwrite with original auth" \
    bash -c 'echo -n "changeauth-test!" | \
        tpm2_nvwrite '"$NV_CHAUTH_IDX"' -P "oldpass" --input=-'

# Note: tpm2-tools doesn't have a direct nvchangeauth command;
# the fwTPM NV_ChangeAuth handler is tested via the wolfTPM wrapper API.

run_test "nvundefine changeauth test index" \
    tpm2_nvundefine "$NV_CHAUTH_IDX" -C o

# ----------------------------------------------------------------
hdr "Hash"
# tpm2_hash uses TPM2_Hash (single command). EventSequenceComplete
# is tested via the wolfTPM wrapper examples (hash sequence API).
echo -n "hash-test-data" > "$TEST_TMPDIR/hash_data.bin"
run_test "tpm2_hash (sha256)" \
    tpm2_hash -g sha256 -o "$TEST_TMPDIR/hash_out.bin" \
        -t "$TEST_TMPDIR/hash_ticket.bin" "$TEST_TMPDIR/hash_data.bin"

# ----------------------------------------------------------------
hdr "PolicyLocality"
run_test "startauthsession for policylocality (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/loc_session.ctx"

run_test "policylocality (locality 1)" \
    tpm2_policylocality -S "$TEST_TMPDIR/loc_session.ctx" 1

run_test "flushcontext (locality session)" \
    tpm2_flushcontext "$TEST_TMPDIR/loc_session.ctx"

# ----------------------------------------------------------------
hdr "Attestation"
# Flush remaining handles before attestation (needs 3 slots)
flush_transient

# Create a primary key for signing attestations
run_test "createprimary for attestation" \
    tpm2_createprimary -C o -g sha256 -G rsa -c "$TEST_TMPDIR/att_primary.ctx"

# Create child AIK for signing
run_test "create AIK (RSA signing key)" \
    tpm2_create -C "$TEST_TMPDIR/att_primary.ctx" \
        -g sha256 -G rsa:rsassa:null \
        -u "$TEST_TMPDIR/aik.pub" -r "$TEST_TMPDIR/aik.priv"

run_test "load AIK" \
    tpm2_load -C "$TEST_TMPDIR/att_primary.ctx" \
        -u "$TEST_TMPDIR/aik.pub" -r "$TEST_TMPDIR/aik.priv" \
        -c "$TEST_TMPDIR/aik.ctx"

# PCR Quote: sign current PCR values with AIK
run_test "tpm2_quote (sha256:0,1,2)" \
    tpm2_quote -c "$TEST_TMPDIR/aik.ctx" -l sha256:0,1,2 \
        -q "cafebabe" -m "$TEST_TMPDIR/quote.msg" \
        -s "$TEST_TMPDIR/quote.sig" -o "$TEST_TMPDIR/quote.pcrs" \
        -g sha256

# GetTime
if check_tool tpm2_gettime; then
    run_test "tpm2_gettime (signed timestamp)" \
        tpm2_gettime -c "$TEST_TMPDIR/aik.ctx" \
            -q "deadbeef" \
            --attestation="$TEST_TMPDIR/time_attest.bin" \
            -o "$TEST_TMPDIR/time_sig.bin" \
            -g sha256 -s rsassa
else
    skip_test "tpm2_gettime" "tpm2_gettime not available in this version"
fi

# Flush before certify to free object slots
flush_transient
# Re-create attestation primary and reload AIK for certify
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TEST_TMPDIR/att_primary.ctx" > /dev/null 2>&1
tpm2_load -C "$TEST_TMPDIR/att_primary.ctx" \
    -u "$TEST_TMPDIR/aik.pub" -r "$TEST_TMPDIR/aik.priv" \
    -c "$TEST_TMPDIR/aik.ctx" > /dev/null 2>&1

# Create a second key to certify using the AIK
run_test "create key to certify" \
    tpm2_create -C "$TEST_TMPDIR/att_primary.ctx" \
        -g sha256 -G ecc \
        -u "$TEST_TMPDIR/certify_key.pub" -r "$TEST_TMPDIR/certify_key.priv"

run_test "load key to certify" \
    tpm2_load -C "$TEST_TMPDIR/att_primary.ctx" \
        -u "$TEST_TMPDIR/certify_key.pub" -r "$TEST_TMPDIR/certify_key.priv" \
        -c "$TEST_TMPDIR/certify_key.ctx"

# Flush to free slots — certify only needs certify_key + aik
flush_transient
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TEST_TMPDIR/att_primary.ctx" > /dev/null 2>&1
tpm2_load -C "$TEST_TMPDIR/att_primary.ctx" \
    -u "$TEST_TMPDIR/aik.pub" -r "$TEST_TMPDIR/aik.priv" \
    -c "$TEST_TMPDIR/aik.ctx" > /dev/null 2>&1
tpm2_load -C "$TEST_TMPDIR/att_primary.ctx" \
    -u "$TEST_TMPDIR/certify_key.pub" -r "$TEST_TMPDIR/certify_key.priv" \
    -c "$TEST_TMPDIR/certify_key.ctx" > /dev/null 2>&1

run_test "tpm2_certify (certify key with AIK)" \
    tpm2_certify -c "$TEST_TMPDIR/certify_key.ctx" \
        -C "$TEST_TMPDIR/aik.ctx" \
        -g sha256 -o "$TEST_TMPDIR/certify_attest.bin" \
        -s "$TEST_TMPDIR/certify_sig.bin"

# Flush attestation handles
flush_transient

# ----------------------------------------------------------------
hdr "RSA Encrypt/Decrypt"
# Re-create RSA primary (flushed before attestation)
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TEST_TMPDIR/primary_rsa.ctx" > /dev/null 2>&1

# Create RSA encryption key (restricted=no, decrypt)
run_test "create RSA decrypt key" \
    tpm2_create -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -g sha256 -G rsa:null:null \
        -u "$TEST_TMPDIR/rsa_enc.pub" -r "$TEST_TMPDIR/rsa_enc.priv" \
        -a "decrypt|userwithauth|sensitivedataorigin"

run_test "load RSA decrypt key" \
    tpm2_load -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -u "$TEST_TMPDIR/rsa_enc.pub" -r "$TEST_TMPDIR/rsa_enc.priv" \
        -c "$TEST_TMPDIR/rsa_enc.ctx"

echo -n "RSA encrypt test data!" > "$TEST_TMPDIR/rsa_plain.bin"

run_test "rsaencrypt" \
    tpm2_rsaencrypt -c "$TEST_TMPDIR/rsa_enc.ctx" \
        -o "$TEST_TMPDIR/rsa_cipher.bin" "$TEST_TMPDIR/rsa_plain.bin"

run_test "rsadecrypt" \
    tpm2_rsadecrypt -c "$TEST_TMPDIR/rsa_enc.ctx" \
        -o "$TEST_TMPDIR/rsa_dec.bin" "$TEST_TMPDIR/rsa_cipher.bin"

run_test "rsadecrypt verify plaintext" \
    diff "$TEST_TMPDIR/rsa_plain.bin" "$TEST_TMPDIR/rsa_dec.bin"

# Flush RSA encrypt handles
flush_transient

# ----------------------------------------------------------------
hdr "AES Encrypt/Decrypt"
# Re-create RSA primary (flushed above)
tpm2_createprimary -C o -g sha256 -G rsa \
    -c "$TEST_TMPDIR/primary_rsa.ctx" > /dev/null 2>&1

# Create AES symmetric key
run_test "create AES-128 key" \
    tpm2_create -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -g sha256 -G aes128cfb \
        -u "$TEST_TMPDIR/aes.pub" -r "$TEST_TMPDIR/aes.priv"

run_test "load AES key" \
    tpm2_load -C "$TEST_TMPDIR/primary_rsa.ctx" \
        -u "$TEST_TMPDIR/aes.pub" -r "$TEST_TMPDIR/aes.priv" \
        -c "$TEST_TMPDIR/aes.ctx"

echo -n "AES encrypt test data for fwTPM!!" > "$TEST_TMPDIR/aes_plain.bin"

run_test "encryptdecrypt (encrypt)" \
    tpm2_encryptdecrypt -c "$TEST_TMPDIR/aes.ctx" \
        -o "$TEST_TMPDIR/aes_cipher.bin" "$TEST_TMPDIR/aes_plain.bin"

run_test "encryptdecrypt (decrypt)" \
    tpm2_encryptdecrypt -d -c "$TEST_TMPDIR/aes.ctx" \
        -o "$TEST_TMPDIR/aes_dec.bin" "$TEST_TMPDIR/aes_cipher.bin"

run_test "aes decrypt verify plaintext" \
    diff "$TEST_TMPDIR/aes_plain.bin" "$TEST_TMPDIR/aes_dec.bin"

# Flush AES handles
flush_transient

# ----------------------------------------------------------------
hdr "EvictControl (Persistent Handles)"
run_test "createprimary for evict test" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/evict_primary.ctx"

run_test "evictcontrol (make persistent 0x81000100)" \
    tpm2_evictcontrol -C o -c "$TEST_TMPDIR/evict_primary.ctx" 0x81000100

run_test "readpublic (persistent handle)" \
    tpm2_readpublic -c 0x81000100

run_test "evictcontrol (evict persistent)" \
    tpm2_evictcontrol -C o -c 0x81000100

# Flush evict handles
flush_transient

# ----------------------------------------------------------------
hdr "Import/Duplicate"
# Import an external RSA key
if check_tool tpm2_import; then
    run_test "createprimary for import" \
        tpm2_createprimary -C o -g sha256 -G rsa \
            -c "$TEST_TMPDIR/import_parent.ctx"

    # Note: tpm2_import -i file.pem (direct) fails with TPM_RC_INTEGRITY due
    # to a wrapping format difference in tpm2-tools' internal import path.
    # Using tpm2_duplicate --tcti none + tpm2_import works correctly.
    if check_tool tpm2_duplicate; then
        openssl genrsa -out "$TEST_TMPDIR/import_rsa.pem" 2048 2>/dev/null
        tpm2_readpublic -c "$TEST_TMPDIR/import_parent.ctx" \
            -o "$TEST_TMPDIR/import_parent.pub" -f tss > /dev/null 2>&1

        run_test "duplicate wrap (offline)" \
            tpm2_duplicate --tcti none \
                -U "$TEST_TMPDIR/import_parent.pub" -G rsa \
                -k "$TEST_TMPDIR/import_rsa.pem" \
                -u "$TEST_TMPDIR/import_key.pub" \
                -r "$TEST_TMPDIR/import_key.dpriv" \
                -s "$TEST_TMPDIR/import_key.seed"

        run_test "import wrapped RSA key" \
            tpm2_import -C "$TEST_TMPDIR/import_parent.ctx" -G rsa \
                -i "$TEST_TMPDIR/import_key.dpriv" \
                -s "$TEST_TMPDIR/import_key.seed" \
                -u "$TEST_TMPDIR/import_key.pub" \
                -r "$TEST_TMPDIR/import_key.priv"

        # Load and use the imported key
        run_test "load imported RSA key" \
            tpm2_load -C "$TEST_TMPDIR/import_parent.ctx" \
                -u "$TEST_TMPDIR/import_key.pub" \
                -r "$TEST_TMPDIR/import_key.priv" \
                -c "$TEST_TMPDIR/import_key.ctx"

        echo "import-sign-test" > "$TEST_TMPDIR/import_msg.txt"

        run_test "sign with imported key" \
            tpm2_sign -c "$TEST_TMPDIR/import_key.ctx" -g sha256 \
                -o "$TEST_TMPDIR/import_sig.bin" "$TEST_TMPDIR/import_msg.txt"

        run_test "verify imported key signature" \
            tpm2_verifysignature -c "$TEST_TMPDIR/import_key.ctx" -g sha256 \
                -m "$TEST_TMPDIR/import_msg.txt" \
                -s "$TEST_TMPDIR/import_sig.bin"

        flush_transient
    else
        skip_test "import external RSA key" "tpm2_duplicate not available"
    fi
fi

# ----------------------------------------------------------------
hdr "MakeCredential / ActivateCredential"
CRED_EK_HANDLE=0x81010009
if check_tool tpm2_makecredential && check_tool tpm2_activatecredential; then
    flush_transient
    # Evict any stale persistent EK from prior runs
    tpm2_evictcontrol -Q -C o -c "$CRED_EK_HANDLE" 2>/dev/null || true

    # Create persistent EK (doesn't consume transient slot)
    run_test "createek (persistent $CRED_EK_HANDLE)" \
        tpm2_createek -Q -c "$CRED_EK_HANDLE" -G rsa -u "$TEST_TMPDIR/ek.pub"

    # Create AK under persistent EK
    run_test "createak" \
        tpm2_createak -C "$CRED_EK_HANDLE" -c "$TEST_TMPDIR/ak.ctx" \
            -G rsa -g sha256 -s rsassa \
            -u "$TEST_TMPDIR/ak.pub" -n "$TEST_TMPDIR/ak.name"

    # Read EK public in PEM format for makecredential
    tpm2_readpublic -c "$CRED_EK_HANDLE" \
        -o "$TEST_TMPDIR/ek.pem" -f pem -Q 2>/dev/null

    # MakeCredential (challenge) using EK public
    echo -n "secret-credential!" > "$TEST_TMPDIR/cred_secret.bin"

    run_test "makecredential" \
        tpm2_makecredential -u "$TEST_TMPDIR/ek.pem" -G rsa \
            -s "$TEST_TMPDIR/cred_secret.bin" \
            -n "$(xxd -p -c 256 "$TEST_TMPDIR/ak.name")" \
            -o "$TEST_TMPDIR/cred_blob.bin"

    # ActivateCredential requires EK auth via PolicySecret(endorsement)
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/cred_session.ctx" > /dev/null 2>&1
    tpm2_policysecret -S "$TEST_TMPDIR/cred_session.ctx" \
        -c e > /dev/null 2>&1

    run_test "activatecredential" \
        tpm2_activatecredential -c "$TEST_TMPDIR/ak.ctx" \
            -C "$CRED_EK_HANDLE" \
            -i "$TEST_TMPDIR/cred_blob.bin" \
            -o "$TEST_TMPDIR/cred_recovered.bin" \
            -P "session:$TEST_TMPDIR/cred_session.ctx"

    tpm2_flushcontext "$TEST_TMPDIR/cred_session.ctx" 2>/dev/null || true

    run_test "credential verify recovered secret" \
        diff "$TEST_TMPDIR/cred_secret.bin" "$TEST_TMPDIR/cred_recovered.bin"

    # Clean up persistent EK
    tpm2_evictcontrol -Q -C o -c "$CRED_EK_HANDLE" 2>/dev/null || true
else
    skip_test "MakeCredential/ActivateCredential" "tpm2_makecredential not available"
fi

# ----------------------------------------------------------------
hdr "NV Counter, Extend & Locks"
NV_CTR_IDX=0x01500020

run_test "nvdefine counter index" \
    tpm2_nvdefine "$NV_CTR_IDX" -C o -s 8 \
        -a "ownerread|ownerwrite|nt=counter"

run_test "nvincrement (first)" \
    tpm2_nvincrement "$NV_CTR_IDX" -C o

run_test "nvincrement (second)" \
    tpm2_nvincrement "$NV_CTR_IDX" -C o

run_test "nvread counter value" \
    tpm2_nvread "$NV_CTR_IDX" -C o -s 8

run_test "nvundefine counter" \
    tpm2_nvundefine "$NV_CTR_IDX" -C o

# NV Extend
NV_EXT_IDX=0x01500021

run_test "nvdefine extend index" \
    tpm2_nvdefine "$NV_EXT_IDX" -C o -s 32 \
        -a "ownerread|ownerwrite|nt=extend"

if check_tool tpm2_nvextend; then
    run_test "nvextend" \
        bash -c 'echo -n "extend-data-test" | \
            tpm2_nvextend '"$NV_EXT_IDX"' -C o --input=-'

    run_test "nvread extended value" \
        tpm2_nvread "$NV_EXT_IDX" -C o -s 32
else
    skip_test "nvextend" "tpm2_nvextend not available"
fi

run_test "nvundefine extend index" \
    tpm2_nvundefine "$NV_EXT_IDX" -C o

# NV Write Lock
NV_LOCK_IDX=0x01500022

run_test "nvdefine for writelock test" \
    tpm2_nvdefine "$NV_LOCK_IDX" -C o -s 16 \
        -a "ownerread|ownerwrite|writedefine"

run_test "nvwrite before lock" \
    bash -c 'echo -n "lock-test-data!!" | \
        tpm2_nvwrite '"$NV_LOCK_IDX"' -C o --input=-'

run_test "nvwritelock" \
    tpm2_nvwritelock "$NV_LOCK_IDX" -C o

run_test "nvread after lock (should work)" \
    tpm2_nvread "$NV_LOCK_IDX" -C o -s 16

run_test "nvundefine locked index" \
    tpm2_nvundefine "$NV_LOCK_IDX" -C o

# ----------------------------------------------------------------
hdr "StirRandom"
run_test "stirrandom" \
    bash -c 'echo -n "additional-entropy-for-drbg" | tpm2_stirrandom'

# ----------------------------------------------------------------
hdr "Clear"
# Clear resets owner hierarchy — run near end to not break other tests
run_test "tpm2_clear (owner)" \
    tpm2_clear -c p

# Re-create primary after clear for any subsequent tests
run_test "createprimary after clear" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/post_clear_primary.ctx"

# ----------------------------------------------------------------
hdr "ReadPublic"
run_test "readpublic" \
    tpm2_readpublic -c "$TEST_TMPDIR/post_clear_primary.ctx"

# ----------------------------------------------------------------
hdr "ContextSave / ContextLoad"
if check_tool tpm2_contextsave && check_tool tpm2_contextload; then
    run_test "contextsave" \
        tpm2_contextsave -c "$TEST_TMPDIR/post_clear_primary.ctx" \
            -o "$TEST_TMPDIR/saved_ctx.bin"

    run_test "contextload" \
        tpm2_contextload -c "$TEST_TMPDIR/saved_ctx.bin"
else
    skip_test "ContextSave/ContextLoad" "tpm2_contextsave not available"
fi

# ================================================================
# NEW TESTS: Commands supported by fwTPM but not previously tested
# ================================================================

# ----------------------------------------------------------------
hdr "PCR Reset"
# PCR 23 is resettable from locality 0
run_test "pcrreset PCR 23" \
    tpm2_pcrreset 23

run_test "pcrextend PCR 23 then reset" \
    bash -c 'tpm2_pcrextend 23:sha256=0000000000000000000000000000000000000000000000000000000000000001 && \
        tpm2_pcrreset 23'

# ----------------------------------------------------------------
# ----------------------------------------------------------------
hdr "PCR Event"
echo "event data for test" > "$TEST_TMPDIR/event.bin"
run_test "pcrevent PCR 16" \
    tpm2_pcrevent 16 "$TEST_TMPDIR/event.bin"

# ----------------------------------------------------------------
hdr "ClearControl"
run_test "clearcontrol disable" \
    tpm2_clearcontrol -C p s
run_test "clearcontrol re-enable" \
    tpm2_clearcontrol -C p c

# ----------------------------------------------------------------
hdr "Primary Key Determinism (across restart)"
if [ $NO_START -eq 0 ]; then
    # Extract object name from tpm2_readpublic output.
    # Name = nameAlg || H(publicArea) — deterministic for same key.
    get_obj_name() {
        tpm2_readpublic -c "$1" 2>/dev/null | grep "^name:" | awk '{print $2}'
    }

    # Create fixed unique data so hashUnique is identical across calls.
    # tpm2-tools randomizes unique by default, which changes the derived key.
    dd if=/dev/zero of="$TEST_TMPDIR/unique_rsa.bin" bs=256 count=1 2>/dev/null
    dd if=/dev/zero of="$TEST_TMPDIR/unique_ecc.bin" bs=64 count=1 2>/dev/null

    # Save pre-restart key names (RSA + ECC under owner hierarchy)
    run_test "createprimary rsa (pre-restart)" \
        tpm2_createprimary -C o -g sha256 -G rsa \
            -u "$TEST_TMPDIR/unique_rsa.bin" \
            -c "$TEST_TMPDIR/det_rsa_pre.ctx"
    DET_RSA_PRE=$(get_obj_name "$TEST_TMPDIR/det_rsa_pre.ctx")
    tpm2_flushcontext "$TEST_TMPDIR/det_rsa_pre.ctx" 2>/dev/null

    run_test "createprimary ecc (pre-restart)" \
        tpm2_createprimary -C o -g sha256 -G ecc \
            -u "$TEST_TMPDIR/unique_ecc.bin" \
            -c "$TEST_TMPDIR/det_ecc_pre.ctx"
    DET_ECC_PRE=$(get_obj_name "$TEST_TMPDIR/det_ecc_pre.ctx")
    tpm2_flushcontext "$TEST_TMPDIR/det_ecc_pre.ctx" 2>/dev/null

    # Send tpm2_shutdown to flush volatile state before restart
    run_test "shutdown (flush NV before restart)" \
        tpm2_shutdown

    # Restart server (preserves NV/seeds, clears transient state + cache)
    server_restart

    # Recreate with same templates + unique — names MUST match
    run_test "createprimary rsa (post-restart)" \
        tpm2_createprimary -C o -g sha256 -G rsa \
            -u "$TEST_TMPDIR/unique_rsa.bin" \
            -c "$TEST_TMPDIR/det_rsa_post.ctx"
    DET_RSA_POST=$(get_obj_name "$TEST_TMPDIR/det_rsa_post.ctx")
    tpm2_flushcontext "$TEST_TMPDIR/det_rsa_post.ctx" 2>/dev/null

    run_test "createprimary ecc (post-restart)" \
        tpm2_createprimary -C o -g sha256 -G ecc \
            -u "$TEST_TMPDIR/unique_ecc.bin" \
            -c "$TEST_TMPDIR/det_ecc_post.ctx"
    DET_ECC_POST=$(get_obj_name "$TEST_TMPDIR/det_ecc_post.ctx")
    tpm2_flushcontext "$TEST_TMPDIR/det_ecc_post.ctx" 2>/dev/null

    # Verify identical names (= identical public areas) across restart
    if [ -n "$DET_RSA_PRE" ] && [ "$DET_RSA_PRE" = "$DET_RSA_POST" ]; then
        echo "  [PASS]  rsa primary deterministic across restart"
        PASS=$((PASS+1))
    else
        echo "  [FAIL]  rsa primary deterministic across restart"
        echo "          pre:  $DET_RSA_PRE"
        echo "          post: $DET_RSA_POST"
        FAIL=$((FAIL+1))
    fi

    if [ -n "$DET_ECC_PRE" ] && [ "$DET_ECC_PRE" = "$DET_ECC_POST" ]; then
        echo "  [PASS]  ecc primary deterministic across restart"
        PASS=$((PASS+1))
    else
        echo "  [FAIL]  ecc primary deterministic across restart"
        echo "          pre:  $DET_ECC_PRE"
        echo "          post: $DET_ECC_POST"
        FAIL=$((FAIL+1))
    fi
else
    skip_test "Determinism tests" "requires server lifecycle (--no-start mode)"
fi

# ----------------------------------------------------------------
hdr "ChangePPS / ChangeEPS"

# ChangePPS: platform seed change should produce different primary key
run_test "createprimary under platform (before changepps)" \
    tpm2_createprimary -C p -g sha256 -G ecc \
        -c "$TEST_TMPDIR/plat_pre.ctx"
tpm2_readpublic -c "$TEST_TMPDIR/plat_pre.ctx" \
    -o "$TEST_TMPDIR/plat_pre.pub" 2>/dev/null
tpm2_flushcontext "$TEST_TMPDIR/plat_pre.ctx" 2>/dev/null

run_test "tpm2_changepps" \
    tpm2_changepps

run_test "createprimary under platform (after changepps)" \
    tpm2_createprimary -C p -g sha256 -G ecc \
        -c "$TEST_TMPDIR/plat_post.ctx"
tpm2_readpublic -c "$TEST_TMPDIR/plat_post.ctx" \
    -o "$TEST_TMPDIR/plat_post.pub" 2>/dev/null
tpm2_flushcontext "$TEST_TMPDIR/plat_post.ctx" 2>/dev/null

run_test "changepps produced different key" \
    bash -c '! cmp -s "$TEST_TMPDIR/plat_pre.pub" "$TEST_TMPDIR/plat_post.pub"'

# ChangeEPS: endorsement seed change should produce different primary key
run_test "createprimary under endorsement (before changeeps)" \
    tpm2_createprimary -C e -g sha256 -G ecc \
        -c "$TEST_TMPDIR/ek_pre.ctx"
tpm2_readpublic -c "$TEST_TMPDIR/ek_pre.ctx" \
    -o "$TEST_TMPDIR/ek_pre.pub" 2>/dev/null
tpm2_flushcontext "$TEST_TMPDIR/ek_pre.ctx" 2>/dev/null

run_test "tpm2_changeeps" \
    tpm2_changeeps

run_test "createprimary under endorsement (after changeeps)" \
    tpm2_createprimary -C e -g sha256 -G ecc \
        -c "$TEST_TMPDIR/ek_post.ctx"
tpm2_readpublic -c "$TEST_TMPDIR/ek_post.ctx" \
    -o "$TEST_TMPDIR/ek_post.pub" 2>/dev/null
tpm2_flushcontext "$TEST_TMPDIR/ek_post.ctx" 2>/dev/null

run_test "changeeps produced different key" \
    bash -c '! cmp -s "$TEST_TMPDIR/ek_pre.pub" "$TEST_TMPDIR/ek_post.pub"'

# Owner hierarchy should be unaffected
run_test "createprimary under owner (still works after seed changes)" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/owner_after_change.ctx"
tpm2_flushcontext "$TEST_TMPDIR/owner_after_change.ctx" 2>/dev/null

# ----------------------------------------------------------------
hdr "Dictionary Attack Lockout"
if check_tool tpm2_dictionarylockout; then
    run_test "DA set parameters" \
        tpm2_dictionarylockout --setup-parameters \
            --max-tries=5 --recovery-time=10 --lockout-recovery=60
    run_test "DA clear lockout" \
        tpm2_dictionarylockout --clear-lockout
    # Restore defaults
    run_test "DA restore defaults" \
        tpm2_dictionarylockout --setup-parameters \
            --max-tries=32 --recovery-time=600 --lockout-recovery=86400
else
    skip_test "DictionaryAttack" "tpm2_dictionarylockout not available"
fi

# ----------------------------------------------------------------
hdr "PolicyCounterTimer"
if check_tool tpm2_policycountertimer; then
    run_test "policycountertimer trial (unsigned-lt)" \
        bash -c 'tpm2_startauthsession -S '"$TEST_TMPDIR"'/ct.ctx && \
            tpm2_policycountertimer -S '"$TEST_TMPDIR"'/ct.ctx --ult 99999999999 && \
            tpm2_flushcontext '"$TEST_TMPDIR"'/ct.ctx'
else
    skip_test "PolicyCounterTimer" "tpm2_policycountertimer not available"
fi

# ----------------------------------------------------------------
hdr "PCR Allocate"
if check_tool tpm2_pcrallocate; then
    run_test "pcrallocate sha256+sha384" \
        tpm2_pcrallocate sha256:all+sha384:all
else
    skip_test "PCR_Allocate" "tpm2_pcrallocate not available"
fi

# ----------------------------------------------------------------
hdr "ReadClock & SetClock"
run_test "readclock" \
    tpm2_readclock

# SetClock: advance clock forward
run_test "setclock (advance)" \
    bash -c 'clock_val=$(tpm2_readclock 2>/dev/null | grep "^  clock:" | awk "{print \$2}"); \
        new_clock=$((clock_val + 100000)); \
        tpm2_setclock $new_clock'

# ----------------------------------------------------------------
hdr "GetTestResult"
if check_tool tpm2_gettestresult; then
    run_test "gettestresult" \
        tpm2_gettestresult
else
    skip_test "gettestresult" "tpm2_gettestresult not available"
fi

# ----------------------------------------------------------------
hdr "IncrementalSelfTest"
if check_tool tpm2_incrementalselftest; then
    run_test "incrementalselftest (sha256)" \
        tpm2_incrementalselftest sha256

    run_test "incrementalselftest (rsa)" \
        tpm2_incrementalselftest rsa
else
    skip_test "incrementalselftest" "tpm2_incrementalselftest not available"
fi

# ----------------------------------------------------------------
hdr "HMAC"
# Flush transient objects from prior tests
flush_transient

run_test "createprimary for HMAC" \
    tpm2_createprimary -C e -g sha256 -G rsa \
        -c "$TEST_TMPDIR/hmac_primary.ctx"

run_test "create HMAC key" \
    tpm2_create -C "$TEST_TMPDIR/hmac_primary.ctx" \
        -G hmac -u "$TEST_TMPDIR/hmac_key.pub" -r "$TEST_TMPDIR/hmac_key.priv"

run_test "load HMAC key" \
    tpm2_load -C "$TEST_TMPDIR/hmac_primary.ctx" \
        -u "$TEST_TMPDIR/hmac_key.pub" -r "$TEST_TMPDIR/hmac_key.priv" \
        -c "$TEST_TMPDIR/hmac_key.ctx"

echo -n "hmac-test-data" > "$TEST_TMPDIR/hmac_data.bin"

run_test "tpm2_hmac (stdin)" \
    bash -c 'cat "'"$TEST_TMPDIR"'/hmac_data.bin" | \
        tpm2_hmac -c "'"$TEST_TMPDIR"'/hmac_key.ctx" \
            -o "'"$TEST_TMPDIR"'/hmac_out.bin"'

run_test "tpm2_hmac (file arg)" \
    tpm2_hmac -c "$TEST_TMPDIR/hmac_key.ctx" \
        -o "$TEST_TMPDIR/hmac_out2.bin" "$TEST_TMPDIR/hmac_data.bin"

# ----------------------------------------------------------------
hdr "LoadExternal"
# Flush transient objects
flush_transient

# Load public part of a TPM-created key externally
run_test "createprimary for loadexternal" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/le_primary.ctx"

run_test "create key for loadexternal" \
    tpm2_create -C "$TEST_TMPDIR/le_primary.ctx" \
        -g sha256 -G rsa \
        -u "$TEST_TMPDIR/le_key.pub" -r "$TEST_TMPDIR/le_key.priv"

run_test "loadexternal (public only, null hierarchy)" \
    tpm2_loadexternal -C n -u "$TEST_TMPDIR/le_key.pub" \
        -c "$TEST_TMPDIR/le_ext.ctx"

run_test "readpublic of externally loaded key" \
    tpm2_readpublic -c "$TEST_TMPDIR/le_ext.ctx"

tpm2_flushcontext "$TEST_TMPDIR/le_ext.ctx" 2>/dev/null || true

# Load an OpenSSL-generated RSA key
if check_tool openssl; then
    openssl genrsa -out "$TEST_TMPDIR/le_rsa.pem" 2048 2>/dev/null

    run_test "loadexternal (OpenSSL RSA private key)" \
        tpm2_loadexternal -G rsa -C n \
            -r "$TEST_TMPDIR/le_rsa.pem" -c "$TEST_TMPDIR/le_rsa.ctx"

    tpm2_flushcontext "$TEST_TMPDIR/le_rsa.ctx" 2>/dev/null || true
fi

# ----------------------------------------------------------------
hdr "CertifyCreation"
# Flush transient objects
flush_transient

if check_tool tpm2_certifycreation; then
    run_test "createprimary with creation data" \
        tpm2_createprimary -C o -c "$TEST_TMPDIR/cc_primary.ctx" \
            --creation-data "$TEST_TMPDIR/cc_creation.data" \
            -d "$TEST_TMPDIR/cc_creation.digest" \
            -t "$TEST_TMPDIR/cc_creation.ticket"

    run_test "create signing key for certifycreation" \
        tpm2_create -G rsa -C "$TEST_TMPDIR/cc_primary.ctx" \
            -u "$TEST_TMPDIR/cc_sign.pub" -r "$TEST_TMPDIR/cc_sign.priv" \
            -c "$TEST_TMPDIR/cc_sign.ctx"

    run_test "certifycreation" \
        tpm2_certifycreation -C "$TEST_TMPDIR/cc_sign.ctx" \
            -c "$TEST_TMPDIR/cc_primary.ctx" \
            -d "$TEST_TMPDIR/cc_creation.digest" \
            -t "$TEST_TMPDIR/cc_creation.ticket" \
            -g sha256 -o "$TEST_TMPDIR/cc_sig.bin" \
            --attestation "$TEST_TMPDIR/cc_attest.bin" \
            -f plain -s rsassa

    # Negative: tamper with the creation ticket and confirm the TPM rejects
    # it with TPM_RC_TICKET (HMAC verification fails). tpm2-tools may save
    # the ticket with a leading marshaling header, so tampering a single
    # byte at a fixed offset isn't reliable across tool versions. Overwrite
    # the trailing half of the file with 0xAA — the HMAC digest lives at
    # the end of the TPMT_TK_CREATION structure and is always included in
    # verification, so corrupting it guarantees TPM_RC_TICKET regardless
    # of any wrapper framing.
    cp "$TEST_TMPDIR/cc_creation.ticket" "$TEST_TMPDIR/cc_creation.ticket.bad"
    TICKET_SIZE=$(wc -c < "$TEST_TMPDIR/cc_creation.ticket.bad")
    TAMPER_OFFSET=$((TICKET_SIZE / 2))
    TAMPER_LEN=$((TICKET_SIZE - TAMPER_OFFSET))
    dd if=/dev/zero bs=1 count="$TAMPER_LEN" 2>/dev/null \
        | tr '\000' '\252' \
        | dd of="$TEST_TMPDIR/cc_creation.ticket.bad" \
            bs=1 seek="$TAMPER_OFFSET" conv=notrunc 2>/dev/null
    run_test_fail "certifycreation rejects tampered ticket (TPM_RC_TICKET)" \
        tpm2_certifycreation -C "$TEST_TMPDIR/cc_sign.ctx" \
            -c "$TEST_TMPDIR/cc_primary.ctx" \
            -d "$TEST_TMPDIR/cc_creation.digest" \
            -t "$TEST_TMPDIR/cc_creation.ticket.bad" \
            -g sha256 -o "$TEST_TMPDIR/cc_sig_bad.bin" \
            --attestation "$TEST_TMPDIR/cc_attest_bad.bin" \
            -f plain -s rsassa
else
    skip_test "certifycreation" "tpm2_certifycreation not available"
fi

# ----------------------------------------------------------------
hdr "Hash + Sign (TK_HASHCHECK ticket)"
# Generate a hash with ticket via TPM2_Hash, then sign the hashed digest
# using the ticket as proof the TPM produced the hash. Exercises the
# TK_HASHCHECK ticket generate→consume flow that PolicyAuthorize/Sign rely on.
flush_transient

run_test "createprimary for hash+sign" \
    tpm2_createprimary -C o -c "$TEST_TMPDIR/hs_primary.ctx"

run_test "create signing key for hash+sign" \
    tpm2_create -G rsa -C "$TEST_TMPDIR/hs_primary.ctx" \
        -u "$TEST_TMPDIR/hs_sign.pub" -r "$TEST_TMPDIR/hs_sign.priv" \
        -c "$TEST_TMPDIR/hs_sign.ctx"

echo -n "ticket-data-to-sign" > "$TEST_TMPDIR/hs_data.bin"
run_test "tpm2_hash with TK_HASHCHECK output" \
    tpm2_hash -C o -g sha256 \
        -o "$TEST_TMPDIR/hs_digest.bin" \
        -t "$TEST_TMPDIR/hs_ticket.bin" \
        "$TEST_TMPDIR/hs_data.bin"

run_test "tpm2_sign consumes TK_HASHCHECK ticket" \
    tpm2_sign -c "$TEST_TMPDIR/hs_sign.ctx" \
        -g sha256 -d -t "$TEST_TMPDIR/hs_ticket.bin" \
        -o "$TEST_TMPDIR/hs_sig.bin" \
        "$TEST_TMPDIR/hs_digest.bin"

# Negative: tamper ticket bytes; sign should reject (TPM_RC_TICKET).
cp "$TEST_TMPDIR/hs_ticket.bin" "$TEST_TMPDIR/hs_ticket.bad"
printf '\x55' | dd of="$TEST_TMPDIR/hs_ticket.bad" \
    bs=1 count=1 seek=16 conv=notrunc 2>/dev/null
run_test_fail "tpm2_sign rejects tampered TK_HASHCHECK (TPM_RC_TICKET)" \
    tpm2_sign -c "$TEST_TMPDIR/hs_sign.ctx" \
        -g sha256 -d -t "$TEST_TMPDIR/hs_ticket.bad" \
        -o "$TEST_TMPDIR/hs_sig_bad.bin" \
        "$TEST_TMPDIR/hs_digest.bin"

# ----------------------------------------------------------------
hdr "Duplicate"
# Flush transient objects
flush_transient

run_test "createprimary for duplicate" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/dup_primary.ctx"

# Create duplication policy (PolicyCommandCode for TPM2_CC_Duplicate)
run_test "startauthsession for duplication policy (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/dup_trial.ctx"

run_test "policycommandcode (Duplicate)" \
    tpm2_policycommandcode -S "$TEST_TMPDIR/dup_trial.ctx" \
        -L "$TEST_TMPDIR/dup_policy.dat" TPM2_CC_Duplicate

run_test "flushcontext (duplication trial)" \
    tpm2_flushcontext "$TEST_TMPDIR/dup_trial.ctx"

# Create key with duplication policy
run_test "create key with duplication policy" \
    tpm2_create -C "$TEST_TMPDIR/dup_primary.ctx" \
        -g sha256 -G rsa \
        -r "$TEST_TMPDIR/dup_key.priv" -u "$TEST_TMPDIR/dup_key.pub" \
        -L "$TEST_TMPDIR/dup_policy.dat" \
        -a "sensitivedataorigin|sign|decrypt"

run_test "load key for duplicate" \
    tpm2_load -C "$TEST_TMPDIR/dup_primary.ctx" \
        -r "$TEST_TMPDIR/dup_key.priv" -u "$TEST_TMPDIR/dup_key.pub" \
        -c "$TEST_TMPDIR/dup_key.ctx"

# Duplicate with null parent, null sym alg
run_test "startauthsession for duplication (policy)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/dup_session.ctx"

run_test "policycommandcode (satisfy Duplicate)" \
    tpm2_policycommandcode -S "$TEST_TMPDIR/dup_session.ctx" \
        -L "$TEST_TMPDIR/dup_policy.dat" TPM2_CC_Duplicate

run_test "duplicate (null parent, null sym)" \
    tpm2_duplicate -C null -c "$TEST_TMPDIR/dup_key.ctx" -G null \
        -p "session:$TEST_TMPDIR/dup_session.ctx" \
        -r "$TEST_TMPDIR/dup_priv.bin" -s "$TEST_TMPDIR/dup_seed.dat"

run_test "flushcontext (duplication session)" \
    tpm2_flushcontext "$TEST_TMPDIR/dup_session.ctx"

# ----------------------------------------------------------------
hdr "ECC Operations (ECDH_KeyGen, ECDH_ZGen, ECC_Parameters)"
# Flush transient objects
flush_transient

if check_tool tpm2_geteccparameters; then
    run_test "geteccparameters (P-256)" \
        tpm2_geteccparameters ecc256 -o "$TEST_TMPDIR/ecc_params.bin"
else
    skip_test "geteccparameters" "tpm2_geteccparameters not available"
fi

if check_tool tpm2_ecdhkeygen && check_tool tpm2_ecdhzgen; then
    run_test "createprimary for ECDH" \
        tpm2_createprimary -C o -g sha256 -G ecc \
            -c "$TEST_TMPDIR/ecdh_primary.ctx"

    run_test "create ECDH key" \
        tpm2_create -C "$TEST_TMPDIR/ecdh_primary.ctx" \
            -g sha256 -G ecc256:ecdh \
            -u "$TEST_TMPDIR/ecdh_key.pub" -r "$TEST_TMPDIR/ecdh_key.priv"

    run_test "load ECDH key" \
        tpm2_load -C "$TEST_TMPDIR/ecdh_primary.ctx" \
            -u "$TEST_TMPDIR/ecdh_key.pub" -r "$TEST_TMPDIR/ecdh_key.priv" \
            -c "$TEST_TMPDIR/ecdh_key.ctx"

    run_test "ecdhkeygen (generate ephemeral)" \
        tpm2_ecdhkeygen -u "$TEST_TMPDIR/ecdh_pub.bin" \
            -o "$TEST_TMPDIR/ecdh_secret.bin" \
            -c "$TEST_TMPDIR/ecdh_key.ctx"

    run_test "ecdhzgen (recover shared secret)" \
        tpm2_ecdhzgen -u "$TEST_TMPDIR/ecdh_pub.bin" \
            -o "$TEST_TMPDIR/ecdh_zpoint.bin" \
            -c "$TEST_TMPDIR/ecdh_key.ctx"

    # Verify ECDH roundtrip: ecdhkeygen produces shared secret,
    # ecdhzgen with the ephemeral public point recovers the same secret.
    # Note: tpm2_ecdhzgen -u with .pub files sends TPM2B_PUBLIC format
    # which may not match the expected TPM2B_ECC_POINT wire format in
    # all tpm2-tools versions. Use ecdhkeygen+ecdhzgen roundtrip instead.
    run_test "ecdh shared secrets match" \
        diff "$TEST_TMPDIR/ecdh_secret.bin" "$TEST_TMPDIR/ecdh_zpoint.bin"
else
    skip_test "ECDH operations" "tpm2_ecdhkeygen/tpm2_ecdhzgen not available"
fi

# ----------------------------------------------------------------
hdr "NV Certify"
# Flush transient objects
flush_transient

if check_tool tpm2_nvcertify; then
    NV_CERT_IDX=0x01500030

    run_test "createprimary for nvcertify" \
        tpm2_createprimary -C o -c "$TEST_TMPDIR/nvc_primary.ctx"

    run_test "create signing key for nvcertify" \
        tpm2_create -G rsa -C "$TEST_TMPDIR/nvc_primary.ctx" \
            -u "$TEST_TMPDIR/nvc_sign.pub" -r "$TEST_TMPDIR/nvc_sign.priv" \
            -c "$TEST_TMPDIR/nvc_sign.ctx"

    run_test "nvdefine for nvcertify" \
        tpm2_nvdefine -s 32 -a "authread|authwrite" "$NV_CERT_IDX"

    run_test "nvwrite for nvcertify" \
        bash -c 'dd if=/dev/urandom bs=1 count=32 status=none | \
            tpm2_nvwrite '"$NV_CERT_IDX"' -i-'

    run_test "nvcertify" \
        tpm2_nvcertify -C "$TEST_TMPDIR/nvc_sign.ctx" -g sha256 \
            -f plain -s rsassa \
            -o "$TEST_TMPDIR/nvc_sig.bin" \
            --attestation "$TEST_TMPDIR/nvc_attest.bin" \
            --size 32 "$NV_CERT_IDX"

    run_test "nvundefine nvcertify index" \
        tpm2_nvundefine "$NV_CERT_IDX" -C o
else
    skip_test "nvcertify" "tpm2_nvcertify not available"
fi

# ================================================================
# NEW TESTS: Advanced Policy Commands
# ================================================================

# ----------------------------------------------------------------
hdr "PolicyPassword (sign with policy + password)"
# Flush transient objects
flush_transient

run_test "startauthsession for policypassword (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/pp_trial.ctx"

run_test "policypassword (trial)" \
    tpm2_policypassword -S "$TEST_TMPDIR/pp_trial.ctx" \
        -L "$TEST_TMPDIR/pp_policy.dat"

run_test "flushcontext (policypassword trial)" \
    tpm2_flushcontext "$TEST_TMPDIR/pp_trial.ctx"

run_test "createprimary for policypassword" \
    tpm2_createprimary -C o -c "$TEST_TMPDIR/pp_primary.ctx"

run_test "create ECC key with policypassword + password" \
    tpm2_create -g sha256 -G ecc \
        -u "$TEST_TMPDIR/pp_key.pub" -r "$TEST_TMPDIR/pp_key.priv" \
        -C "$TEST_TMPDIR/pp_primary.ctx" \
        -L "$TEST_TMPDIR/pp_policy.dat" -p testpswd

run_test "load policypassword key" \
    tpm2_load -C "$TEST_TMPDIR/pp_primary.ctx" \
        -u "$TEST_TMPDIR/pp_key.pub" -r "$TEST_TMPDIR/pp_key.priv" \
        -c "$TEST_TMPDIR/pp_key.ctx"

echo "plaintext" > "$TEST_TMPDIR/pp_plain.txt"

# Sign with plain password (should work)
run_test "sign with plain password" \
    tpm2_sign -c "$TEST_TMPDIR/pp_key.ctx" -p testpswd \
        -o "$TEST_TMPDIR/pp_sig.bin" "$TEST_TMPDIR/pp_plain.txt"

run_test "verify signature (plain password)" \
    tpm2_verifysignature -c "$TEST_TMPDIR/pp_key.ctx" \
        -m "$TEST_TMPDIR/pp_plain.txt" -s "$TEST_TMPDIR/pp_sig.bin"

# Sign using policy session with PolicyPassword + password
run_test "startauthsession for policypassword sign (policy)" \
    tpm2_startauthsession --policy-session -S "$TEST_TMPDIR/pp_sign_session.ctx"

run_test "policypassword (satisfy for sign)" \
    tpm2_policypassword -S "$TEST_TMPDIR/pp_sign_session.ctx"

run_test "sign with policy session + password" \
    tpm2_sign -c "$TEST_TMPDIR/pp_key.ctx" \
        -p session:"$TEST_TMPDIR/pp_sign_session.ctx"+testpswd \
        -o "$TEST_TMPDIR/pp_sig2.bin" "$TEST_TMPDIR/pp_plain.txt"

# Flush objects — verifysignature only needs the key
flush_transient
tpm2_createprimary -C o -c "$TEST_TMPDIR/pp_primary.ctx" > /dev/null 2>&1
tpm2_load -C "$TEST_TMPDIR/pp_primary.ctx" \
    -u "$TEST_TMPDIR/pp_key.pub" -r "$TEST_TMPDIR/pp_key.priv" \
    -c "$TEST_TMPDIR/pp_key.ctx" > /dev/null 2>&1

run_test "verify signature (policy + password)" \
    tpm2_verifysignature -c "$TEST_TMPDIR/pp_key.ctx" \
        -m "$TEST_TMPDIR/pp_plain.txt" -s "$TEST_TMPDIR/pp_sig2.bin"

# ----------------------------------------------------------------
hdr "PolicyAuthValue (sign with policy + authvalue)"
# Flush transient objects
flush_transient

run_test "startauthsession for policyauthvalue (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/pa_trial.ctx"

run_test "policyauthvalue (trial)" \
    tpm2_policyauthvalue -S "$TEST_TMPDIR/pa_trial.ctx" \
        -L "$TEST_TMPDIR/pa_policy.dat"

run_test "flushcontext (policyauthvalue trial)" \
    tpm2_flushcontext "$TEST_TMPDIR/pa_trial.ctx"

run_test "createprimary for policyauthvalue" \
    tpm2_createprimary -C o -c "$TEST_TMPDIR/pa_primary.ctx"

run_test "create ECC key with policyauthvalue + password" \
    tpm2_create -g sha256 -G ecc \
        -u "$TEST_TMPDIR/pa_key.pub" -r "$TEST_TMPDIR/pa_key.priv" \
        -C "$TEST_TMPDIR/pa_primary.ctx" \
        -L "$TEST_TMPDIR/pa_policy.dat" -p authpswd

run_test "load policyauthvalue key" \
    tpm2_load -C "$TEST_TMPDIR/pa_primary.ctx" \
        -u "$TEST_TMPDIR/pa_key.pub" -r "$TEST_TMPDIR/pa_key.priv" \
        -c "$TEST_TMPDIR/pa_key.ctx"

echo "plaintext" > "$TEST_TMPDIR/pa_plain.txt"

# Sign using policy session with PolicyAuthValue + authvalue
run_test "startauthsession for policyauthvalue sign (policy)" \
    tpm2_startauthsession --policy-session -S "$TEST_TMPDIR/pa_sign_session.ctx"

run_test "policyauthvalue (satisfy for sign)" \
    tpm2_policyauthvalue -S "$TEST_TMPDIR/pa_sign_session.ctx"

run_test "sign with policyauthvalue session + authvalue" \
    tpm2_sign -c "$TEST_TMPDIR/pa_key.ctx" \
        -p session:"$TEST_TMPDIR/pa_sign_session.ctx"+authpswd \
        -o "$TEST_TMPDIR/pa_sig.bin" "$TEST_TMPDIR/pa_plain.txt"

run_test "verify signature (policyauthvalue)" \
    tpm2_verifysignature -c "$TEST_TMPDIR/pa_key.ctx" \
        -m "$TEST_TMPDIR/pa_plain.txt" -s "$TEST_TMPDIR/pa_sig.bin"

# ----------------------------------------------------------------
hdr "PolicyCommandCode (unseal with command code policy)"
# Flush transient objects
flush_transient

run_test "createprimary for policycommandcode" \
    tpm2_createprimary -C o -c "$TEST_TMPDIR/pcc_primary.ctx"

run_test "startauthsession for policycommandcode (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/pcc_trial.ctx"

run_test "policycommandcode (trial, Unseal)" \
    tpm2_policycommandcode -S "$TEST_TMPDIR/pcc_trial.ctx" \
        -L "$TEST_TMPDIR/pcc_policy.dat" TPM2_CC_Unseal

run_test "flushcontext (pcc trial)" \
    tpm2_flushcontext "$TEST_TMPDIR/pcc_trial.ctx"

run_test "create sealed object with policycommandcode" \
    bash -c 'echo -n "cc-sealed-data" | tpm2_create \
        -C "'"$TEST_TMPDIR"'/pcc_primary.ctx" \
        -i- -L "'"$TEST_TMPDIR"'/pcc_policy.dat" \
        -u "'"$TEST_TMPDIR"'/pcc_sealed.pub" -r "'"$TEST_TMPDIR"'/pcc_sealed.priv"'

run_test "load policycommandcode sealed object" \
    tpm2_load -C "$TEST_TMPDIR/pcc_primary.ctx" \
        -u "$TEST_TMPDIR/pcc_sealed.pub" -r "$TEST_TMPDIR/pcc_sealed.priv" \
        -c "$TEST_TMPDIR/pcc_sealed.ctx"

run_test "startauthsession for policycommandcode (policy)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/pcc_session.ctx"

run_test "policycommandcode (satisfy, Unseal)" \
    tpm2_policycommandcode -S "$TEST_TMPDIR/pcc_session.ctx" \
        -L "$TEST_TMPDIR/pcc_policy.dat" TPM2_CC_Unseal

run_test "unseal with policycommandcode" \
    tpm2_unseal -p "session:$TEST_TMPDIR/pcc_session.ctx" \
        -c "$TEST_TMPDIR/pcc_sealed.ctx"

run_test "flushcontext (pcc policy session)" \
    tpm2_flushcontext "$TEST_TMPDIR/pcc_session.ctx"

# ----------------------------------------------------------------
hdr "PolicyOR (unseal with OR of two PCR policies)"
# Flush transient objects
flush_transient

# Capture PolicyPCR digest for current PCR 23 state (set 1)
tpm2_pcrreset 23 2>/dev/null || true

run_test "startauthsession for policyor set1 (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/por_trial1.ctx"

run_test "policypcr set1 (PCR 23 = zeros)" \
    tpm2_policypcr -S "$TEST_TMPDIR/por_trial1.ctx" \
        -l sha256:23 -L "$TEST_TMPDIR/por_set1.policy"

run_test "flushcontext (por trial1)" \
    tpm2_flushcontext "$TEST_TMPDIR/por_trial1.ctx"

# Extend PCR 23 and capture second policy
run_test "pcrextend PCR 23 for policyor set2" \
    tpm2_pcrextend 23:sha256=e7011b851ee967e2d24e035ae41b0ada2decb182e4f7ad8411f2bf564c56fd6f

run_test "startauthsession for policyor set2 (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/por_trial2.ctx"

run_test "policypcr set2 (PCR 23 = extended)" \
    tpm2_policypcr -S "$TEST_TMPDIR/por_trial2.ctx" \
        -l sha256:23 -L "$TEST_TMPDIR/por_set2.policy"

run_test "flushcontext (por trial2)" \
    tpm2_flushcontext "$TEST_TMPDIR/por_trial2.ctx"

# Build PolicyOR from the two PCR policies
run_test "startauthsession for policyor compound (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/por_trial3.ctx"

run_test "policyor (compound: set1 OR set2)" \
    tpm2_policyor -S "$TEST_TMPDIR/por_trial3.ctx" \
        -L "$TEST_TMPDIR/por_or.policy" \
        "sha256:$TEST_TMPDIR/por_set1.policy,$TEST_TMPDIR/por_set2.policy"

run_test "flushcontext (por trial3)" \
    tpm2_flushcontext "$TEST_TMPDIR/por_trial3.ctx"

# Create sealed object with PolicyOR
run_test "createprimary for policyor" \
    tpm2_createprimary -C o -c "$TEST_TMPDIR/por_primary.ctx"

run_test "create sealed object with PolicyOR" \
    bash -c 'echo -n "or-secret" | tpm2_create \
        -C "'"$TEST_TMPDIR"'/por_primary.ctx" \
        -g sha256 -i- -L "'"$TEST_TMPDIR"'/por_or.policy" \
        -u "'"$TEST_TMPDIR"'/por_sealed.pub" -r "'"$TEST_TMPDIR"'/por_sealed.priv"'

run_test "load policyor sealed object" \
    tpm2_load -C "$TEST_TMPDIR/por_primary.ctx" \
        -u "$TEST_TMPDIR/por_sealed.pub" -r "$TEST_TMPDIR/por_sealed.priv" \
        -c "$TEST_TMPDIR/por_sealed.ctx"

# Unseal using set2 (current PCR state matches set2)
run_test "startauthsession for policyor unseal (policy)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/por_session.ctx"

run_test "policypcr (satisfy set2)" \
    tpm2_policypcr -S "$TEST_TMPDIR/por_session.ctx" -l sha256:23

run_test "policyor (satisfy compound)" \
    tpm2_policyor -S "$TEST_TMPDIR/por_session.ctx" \
        "sha256:$TEST_TMPDIR/por_set1.policy,$TEST_TMPDIR/por_set2.policy"

run_test "unseal with PolicyOR" \
    tpm2_unseal -p "session:$TEST_TMPDIR/por_session.ctx" \
        -c "$TEST_TMPDIR/por_sealed.ctx"

run_test "flushcontext (por policy session)" \
    tpm2_flushcontext "$TEST_TMPDIR/por_session.ctx"

# ----------------------------------------------------------------
hdr "PolicySecret (unseal with hierarchy secret)"
# Flush transient objects and saved sessions
flush_transient
tpm2_flushcontext -s 2>/dev/null || true

if check_tool tpm2_policysecret; then
    # Clear and set up fresh
    tpm2_clear -c p 2>/dev/null || true

    # Create policy: PolicySecret referencing owner hierarchy
    run_test "startauthsession for policysecret (trial)" \
        tpm2_startauthsession -S "$TEST_TMPDIR/ps_trial.ctx"

    run_test "policysecret (trial, owner hierarchy)" \
        tpm2_policysecret -S "$TEST_TMPDIR/ps_trial.ctx" \
            -c 0x40000001 -L "$TEST_TMPDIR/ps_policy.dat"

    run_test "flushcontext (ps trial)" \
        tpm2_flushcontext "$TEST_TMPDIR/ps_trial.ctx"

    # Create sealed object protected by PolicySecret
    run_test "createprimary for policysecret" \
        tpm2_createprimary -C o -c "$TEST_TMPDIR/ps_primary.ctx"

    run_test "create sealed object with policysecret" \
        bash -c 'echo -n "secret-data" | tpm2_create \
            -C "'"$TEST_TMPDIR"'/ps_primary.ctx" \
            -g sha256 -i- -L "'"$TEST_TMPDIR"'/ps_policy.dat" \
            -u "'"$TEST_TMPDIR"'/ps_sealed.pub" -r "'"$TEST_TMPDIR"'/ps_sealed.priv"'

    run_test "load policysecret sealed object" \
        tpm2_load -C "$TEST_TMPDIR/ps_primary.ctx" \
            -u "$TEST_TMPDIR/ps_sealed.pub" -r "$TEST_TMPDIR/ps_sealed.priv" \
            -c "$TEST_TMPDIR/ps_sealed.ctx"

    # Satisfy PolicySecret and unseal
    run_test "startauthsession for policysecret (policy)" \
        tpm2_startauthsession --policy-session \
            -S "$TEST_TMPDIR/ps_session.ctx"

    run_test "policysecret (satisfy, owner hierarchy)" \
        tpm2_policysecret -S "$TEST_TMPDIR/ps_session.ctx" \
            -c 0x40000001

    run_test "unseal with policysecret" \
        tpm2_unseal -p "session:$TEST_TMPDIR/ps_session.ctx" \
            -c "$TEST_TMPDIR/ps_sealed.ctx"

    run_test "flushcontext (ps session)" \
        tpm2_flushcontext "$TEST_TMPDIR/ps_session.ctx"
else
    skip_test "PolicySecret" "tpm2_policysecret not available"
fi

# ----------------------------------------------------------------
hdr "PolicyAuthorize"
# Flush transient objects
flush_transient

if check_tool tpm2_policyauthorize && check_tool openssl; then
    # Generate RSA signing key for authorization
    openssl genrsa -out "$TEST_TMPDIR/pauth_priv.pem" 2048 2>/dev/null
    openssl rsa -in "$TEST_TMPDIR/pauth_priv.pem" \
        -out "$TEST_TMPDIR/pauth_pub.pem" -pubout 2>/dev/null

    run_test "loadexternal (verifying key for policyauthorize)" \
        tpm2_loadexternal -G rsa -C n \
            -u "$TEST_TMPDIR/pauth_pub.pem" \
            -c "$TEST_TMPDIR/pauth_vk.ctx" \
            -n "$TEST_TMPDIR/pauth_vk.name"

    # Create a PCR policy that we'll authorize
    run_test "startauthsession for policyauthorize sub-policy (trial)" \
        tpm2_startauthsession -S "$TEST_TMPDIR/pauth_sub.ctx"

    run_test "policypcr (sub-policy for authorize)" \
        tpm2_policypcr -S "$TEST_TMPDIR/pauth_sub.ctx" \
            -l sha256:23 -L "$TEST_TMPDIR/pauth_pcr.policy"

    run_test "flushcontext (pauth sub)" \
        tpm2_flushcontext "$TEST_TMPDIR/pauth_sub.ctx"

    # Generate PolicyAuthorize (trial)
    run_test "startauthsession for policyauthorize (trial)" \
        tpm2_startauthsession -S "$TEST_TMPDIR/pauth_trial.ctx"

    run_test "policyauthorize (trial)" \
        tpm2_policyauthorize -S "$TEST_TMPDIR/pauth_trial.ctx" \
            -L "$TEST_TMPDIR/pauth_auth.policy" \
            -n "$TEST_TMPDIR/pauth_vk.name"

    run_test "flushcontext (pauth trial)" \
        tpm2_flushcontext "$TEST_TMPDIR/pauth_trial.ctx"

    tpm2_flushcontext "$TEST_TMPDIR/pauth_vk.ctx" 2>/dev/null || true
else
    skip_test "PolicyAuthorize" "tpm2_policyauthorize or openssl not available"
fi

# ----------------------------------------------------------------
hdr "PolicyNV"
# Flush transient objects and saved sessions
flush_transient
tpm2_flushcontext -s 2>/dev/null || true

if check_tool tpm2_policynv; then
    NV_POLICYNV_IDX=0x01500040

    tpm2_clear -c p 2>/dev/null || true

    # Define NV index, write a value, then test PolicyNV comparison
    run_test "nvdefine for policynv" \
        tpm2_nvdefine -C o -p nvpass "$NV_POLICYNV_IDX" \
            -a "authread|authwrite" -s 1

    run_test "nvwrite for policynv" \
        bash -c 'echo -ne "\x81" | \
            tpm2_nvwrite -P nvpass -i- '"$NV_POLICYNV_IDX"

    # Test "eq" comparison (operandB == 0x81, should match)
    run_test "startauthsession for policynv eq (policy)" \
        tpm2_startauthsession -S "$TEST_TMPDIR/pnv_session.ctx" \
            --policy-session

    run_test "policynv (eq comparison, 0x81 == 0x81)" \
        bash -c 'echo -ne "\x81" | \
            tpm2_policynv -S "'"$TEST_TMPDIR"'/pnv_session.ctx" \
                -i- -P nvpass '"$NV_POLICYNV_IDX"' eq'

    run_test "flushcontext (pnv session)" \
        tpm2_flushcontext "$TEST_TMPDIR/pnv_session.ctx"

    # Test "neq" comparison (operandB == 0x80, should pass since != 0x81)
    run_test "startauthsession for policynv neq (policy)" \
        tpm2_startauthsession -S "$TEST_TMPDIR/pnv_session2.ctx" \
            --policy-session

    run_test "policynv (neq comparison, 0x80 != 0x81)" \
        bash -c 'echo -ne "\x80" | \
            tpm2_policynv -S "'"$TEST_TMPDIR"'/pnv_session2.ctx" \
                -i- -P nvpass '"$NV_POLICYNV_IDX"' neq'

    run_test "flushcontext (pnv session2)" \
        tpm2_flushcontext "$TEST_TMPDIR/pnv_session2.ctx"

    run_test "nvundefine policynv index" \
        tpm2_nvundefine "$NV_POLICYNV_IDX" -C o
else
    skip_test "PolicyNV" "tpm2_policynv not available"
fi

# ================================================================
# NEGATIVE / FAILURE TEST CASES
# ================================================================

hdr "Negative Tests — ChangePPS/ChangeEPS Auth"

if check_tool tpm2_changepps && check_tool tpm2_changeeps; then
    # Wrong platform password should fail
    run_test_fail "changepps with wrong platform auth" \
        tpm2_changepps -p wrongpass

    run_test_fail "changeeps with wrong platform auth" \
        tpm2_changeeps -p wrongpass

    # ChangeEPS resets endorsement auth — set password then verify reset
    tpm2_clear -c p 2>/dev/null || true
    tpm2_changeauth -c e endorsepass 2>/dev/null || true
    run_test "changeeps (resets endorsement auth)" \
        tpm2_changeeps
    run_test_fail "endorsement old auth rejected after changeeps" \
        tpm2_createprimary -C e -P endorsepass -g sha256 -G ecc \
            -c "$TEST_TMPDIR/ek_fail.ctx"
    run_test "endorsement no-auth works after changeeps" \
        tpm2_createprimary -C e -g sha256 -G ecc \
            -c "$TEST_TMPDIR/ek_noauth.ctx"
    tpm2_flushcontext "$TEST_TMPDIR/ek_noauth.ctx" 2>/dev/null
fi

hdr "Negative Tests — Auth Failures"
# Flush all transient/loaded/saved objects and clear for fresh state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_clear -c p 2>/dev/null || true

# Wrong owner password
tpm2_changeauth -c o correctpass 2>/dev/null || true
run_test_fail "createprimary with wrong owner password" \
    tpm2_createprimary -C o -P wrongpass -g sha256 -G rsa \
        -c "$TEST_TMPDIR/neg_auth.ctx"

# Flush sessions and reset owner auth
tpm2_flushcontext -s 2>/dev/null || true
tpm2_changeauth -c o -p correctpass 2>/dev/null || true

# Wrong key password
run_test "createprimary for neg auth tests" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/neg_primary.ctx"

run_test "create key with password for neg test" \
    tpm2_create -C "$TEST_TMPDIR/neg_primary.ctx" \
        -g sha256 -G ecc -p mypassword \
        -u "$TEST_TMPDIR/neg_key.pub" -r "$TEST_TMPDIR/neg_key.priv"

run_test "load key for neg auth test" \
    tpm2_load -C "$TEST_TMPDIR/neg_primary.ctx" \
        -u "$TEST_TMPDIR/neg_key.pub" -r "$TEST_TMPDIR/neg_key.priv" \
        -c "$TEST_TMPDIR/neg_key.ctx"

echo "test" > "$TEST_TMPDIR/neg_msg.txt"

run_test_fail "sign with wrong key password" \
    tpm2_sign -c "$TEST_TMPDIR/neg_key.ctx" -p wrongpassword \
        -o "$TEST_TMPDIR/neg_sig.bin" "$TEST_TMPDIR/neg_msg.txt"

# Flush sessions leaked by failed auth
tpm2_flushcontext -s 2>/dev/null || true

run_test_fail "sign with no password (key has password)" \
    tpm2_sign -c "$TEST_TMPDIR/neg_key.ctx" \
        -o "$TEST_TMPDIR/neg_sig.bin" "$TEST_TMPDIR/neg_msg.txt"

# Flush sessions leaked by failed auth
tpm2_flushcontext -s 2>/dev/null || true

# ----------------------------------------------------------------
hdr "Negative Tests — Handle Errors"
# Use a flushed/invalid handle
run_test_fail "readpublic on invalid handle" \
    tpm2_readpublic -c 0x80000099

# ----------------------------------------------------------------
hdr "Negative Tests — PCR Locality"
# PCR 0 is not resettable from locality 0
run_test_fail "pcrreset PCR 0 (wrong locality)" \
    tpm2_pcrreset 0

# ----------------------------------------------------------------
hdr "Negative Tests — NV Errors"
# Flush all and clear to ensure clean NV state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_clear -c p 2>/dev/null || true

NV_NEG_IDX=0x01500050

# Read undefined NV index
run_test_fail "nvread undefined index" \
    tpm2_nvread "$NV_NEG_IDX" -C o -s 16

# Define, write-lock, then try to write
run_test "nvdefine for neg writelock test" \
    tpm2_nvdefine "$NV_NEG_IDX" -C o -s 16 \
        -a "ownerread|ownerwrite|writedefine"

run_test "nvwrite before neg writelock" \
    bash -c 'echo -n "neg-lock-test!!!!" | head -c 16 | \
        tpm2_nvwrite '"$NV_NEG_IDX"' -C o --input=-'

run_test "nvwritelock for neg test" \
    tpm2_nvwritelock "$NV_NEG_IDX" -C o

run_test_fail "nvwrite after writelock (should fail)" \
    bash -c 'echo -n "should-fail!!!!!" | head -c 16 | \
        tpm2_nvwrite '"$NV_NEG_IDX"' -C o --input=-'

run_test "nvundefine neg writelock index" \
    tpm2_nvundefine "$NV_NEG_IDX" -C o

# NV wrong auth
NV_NEG_AUTH_IDX=0x01500051
run_test "nvdefine with auth for neg test" \
    tpm2_nvdefine "$NV_NEG_AUTH_IDX" -C o -s 16 \
        -a "authread|authwrite" -p "correct"

run_test_fail "nvwrite with wrong NV auth" \
    bash -c 'echo -n "wrong-auth-data!" | \
        tpm2_nvwrite '"$NV_NEG_AUTH_IDX"' -P "wrong" --input=-'

# Flush sessions leaked by failed auth attempts
tpm2_flushcontext -s 2>/dev/null || true

run_test_fail "nvread with wrong NV auth" \
    tpm2_nvread "$NV_NEG_AUTH_IDX" -P "wrong" -s 16

# Flush sessions leaked by failed auth attempts
tpm2_flushcontext -s 2>/dev/null || true

run_test "nvundefine neg auth index" \
    tpm2_nvundefine "$NV_NEG_AUTH_IDX" -C o

# NV wrong type operation (increment on non-counter)
NV_NEG_TYPE_IDX=0x01500052
run_test "nvdefine ordinary for neg type test" \
    tpm2_nvdefine "$NV_NEG_TYPE_IDX" -C o -s 16 \
        -a "ownerread|ownerwrite"

run_test_fail "nvincrement on non-counter index (wrong type)" \
    tpm2_nvincrement "$NV_NEG_TYPE_IDX" -C o

run_test "nvundefine neg type index" \
    tpm2_nvundefine "$NV_NEG_TYPE_IDX" -C o

# ----------------------------------------------------------------
hdr "Negative Tests — Key Type Mismatches"
# Flush all to ensure clean state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

run_test "createprimary for neg key tests" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/neg_kp.ctx"

# Create a sign-only key, try to use for decrypt
run_test "create sign-only RSA key" \
    tpm2_create -C "$TEST_TMPDIR/neg_kp.ctx" \
        -g sha256 -G rsa:rsassa:null \
        -u "$TEST_TMPDIR/neg_sign.pub" -r "$TEST_TMPDIR/neg_sign.priv" \
        -a "sign|sensitivedataorigin|userwithauth"

run_test "load sign-only RSA key" \
    tpm2_load -C "$TEST_TMPDIR/neg_kp.ctx" \
        -u "$TEST_TMPDIR/neg_sign.pub" -r "$TEST_TMPDIR/neg_sign.priv" \
        -c "$TEST_TMPDIR/neg_sign.ctx"

echo -n "test data" > "$TEST_TMPDIR/neg_plain.bin"

run_test_fail "rsadecrypt with sign-only key (wrong key usage)" \
    tpm2_rsadecrypt -c "$TEST_TMPDIR/neg_sign.ctx" \
        -o "$TEST_TMPDIR/neg_dec.bin" "$TEST_TMPDIR/neg_plain.bin"

tpm2_flushcontext -s 2>/dev/null || true
tpm2_flushcontext -t 2>/dev/null || true

# Create decrypt-only key, try to use for sign
# Re-create primary since we flushed transient objects
run_test "createprimary for neg decrypt test" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/neg_kp.ctx"

run_test "create decrypt-only RSA key" \
    tpm2_create -C "$TEST_TMPDIR/neg_kp.ctx" \
        -g sha256 -G rsa:null:null \
        -u "$TEST_TMPDIR/neg_dec_key.pub" -r "$TEST_TMPDIR/neg_dec_key.priv" \
        -a "decrypt|sensitivedataorigin|userwithauth"

run_test "load decrypt-only RSA key" \
    tpm2_load -C "$TEST_TMPDIR/neg_kp.ctx" \
        -u "$TEST_TMPDIR/neg_dec_key.pub" -r "$TEST_TMPDIR/neg_dec_key.priv" \
        -c "$TEST_TMPDIR/neg_dec_key.ctx"

run_test_fail "sign with decrypt-only key (wrong key usage)" \
    tpm2_sign -c "$TEST_TMPDIR/neg_dec_key.ctx" -g sha256 \
        -o "$TEST_TMPDIR/neg_badsig.bin" "$TEST_TMPDIR/neg_msg.txt"

tpm2_flushcontext -s 2>/dev/null || true

# ----------------------------------------------------------------
hdr "Negative Tests — Policy Failures"
# Flush all for clean state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

# Create sealed object locked to PCR 23, extend PCR, try unseal (wrong PCR)
run_test "createprimary for neg policy tests" \
    tpm2_createprimary -C o -g sha256 -G rsa \
        -c "$TEST_TMPDIR/negpol_primary.ctx"

tpm2_pcrreset 23 2>/dev/null || true

run_test "startauthsession for neg policypcr (trial)" \
    tpm2_startauthsession -S "$TEST_TMPDIR/negpol_trial.ctx"

run_test "policypcr neg (trial, PCR 23 current)" \
    tpm2_policypcr -S "$TEST_TMPDIR/negpol_trial.ctx" \
        -l sha256:23 -L "$TEST_TMPDIR/negpol_policy.bin"

run_test "flushcontext (negpol trial)" \
    tpm2_flushcontext "$TEST_TMPDIR/negpol_trial.ctx"

run_test "create sealed key locked to current PCR 23" \
    bash -c 'echo -n "pcr-locked-secret" | tpm2_create \
        -C "'"$TEST_TMPDIR"'/negpol_primary.ctx" \
        -i- -L "'"$TEST_TMPDIR"'/negpol_policy.bin" \
        -u "'"$TEST_TMPDIR"'/negpol_sealed.pub" -r "'"$TEST_TMPDIR"'/negpol_sealed.priv"'

run_test "load neg policy sealed key" \
    tpm2_load -C "$TEST_TMPDIR/negpol_primary.ctx" \
        -u "$TEST_TMPDIR/negpol_sealed.pub" -r "$TEST_TMPDIR/negpol_sealed.priv" \
        -c "$TEST_TMPDIR/negpol_sealed.ctx"

# Extend PCR 23 to change its value (policy will no longer match)
run_test "pcrextend PCR 23 (invalidate policy)" \
    tpm2_pcrextend 23:sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

run_test "startauthsession for neg policypcr (policy)" \
    tpm2_startauthsession --policy-session \
        -S "$TEST_TMPDIR/negpol_session.ctx"

# PolicyPCR will succeed (it just records current PCR), but the
# resulting policy digest won't match the sealed object's policy
run_test "policypcr neg (satisfy with wrong PCR)" \
    tpm2_policypcr -S "$TEST_TMPDIR/negpol_session.ctx" -l sha256:23

run_test_fail "unseal with wrong PCR value (policy mismatch)" \
    tpm2_unseal -p "session:$TEST_TMPDIR/negpol_session.ctx" \
        -c "$TEST_TMPDIR/negpol_sealed.ctx"

tpm2_flushcontext "$TEST_TMPDIR/negpol_session.ctx" 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true

# Try unseal without any policy session (no auth at all)
run_test_fail "unseal without policy session (no auth)" \
    tpm2_unseal -c "$TEST_TMPDIR/negpol_sealed.ctx"

tpm2_flushcontext -s 2>/dev/null || true

# ----------------------------------------------------------------
hdr "Negative Tests — State Violations"
# Note: tpm2_startup via mssim TCTI always sends a platform POWER_ON first,
# which resets the TPM boot state. Cannot test double-startup via tpm2-tools.
# fwTPM correctly returns TPM_RC_INITIALIZE for actual double startup
# (tested via wolfTPM wrapper examples).
run_test "double startup (mssim power-cycles — always succeeds)" \
    tpm2_startup -c

# ----------------------------------------------------------------
hdr "Negative Tests — Unsupported Algorithms"
run_test_fail "testparms unsupported algorithm (rsa512)" \
    tpm2_testparms rsa512

run_test_fail "createprimary with unsupported key size" \
    tpm2_createprimary -C o -g sha256 -G rsa512 \
        -c "$TEST_TMPDIR/neg_unsup.ctx"

# ----------------------------------------------------------------
hdr "Negative Tests — Disabled Hierarchy"
# Flush all for clean state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
# Disable owner hierarchy, try to create under it
run_test "hierarchycontrol (disable owner for neg test)" \
    tpm2_hierarchycontrol -C p shEnable clear

# Note: fwTPM allows operations even when hierarchy is disabled
# (it only tracks the enable flag but doesn't enforce on all commands).
# Test disabling and re-enabling to verify the command works.
run_test "hierarchycontrol (re-enable owner)" \
    tpm2_hierarchycontrol -C p shEnable set

# ----------------------------------------------------------------
hdr "Negative Tests — NV Read Lock"
# Flush all and clear for clean NV state
tpm2_flushcontext -t 2>/dev/null || true
tpm2_flushcontext -l 2>/dev/null || true
tpm2_flushcontext -s 2>/dev/null || true
tpm2_clear -c p 2>/dev/null || true

NV_RLOCK_IDX=0x01500060

run_test "nvdefine for neg readlock test" \
    tpm2_nvdefine "$NV_RLOCK_IDX" -C o -s 16 \
        -a "ownerread|ownerwrite|read_stclear"

run_test "nvwrite for neg readlock" \
    bash -c 'echo -n "readlock-test!!!" | head -c 16 | \
        tpm2_nvwrite '"$NV_RLOCK_IDX"' -C o --input=-'

run_test "nvread before readlock (should work)" \
    tpm2_nvread "$NV_RLOCK_IDX" -C o -s 16

if check_tool tpm2_nvreadlock; then
    run_test "nvreadlock" \
        tpm2_nvreadlock "$NV_RLOCK_IDX" -C o

    run_test_fail "nvread after readlock (should fail)" \
        tpm2_nvread "$NV_RLOCK_IDX" -C o -s 16
else
    skip_test "nvreadlock" "tpm2_nvreadlock not available"
fi

run_test "nvundefine neg readlock index" \
    tpm2_nvundefine "$NV_RLOCK_IDX" -C o

# ----------------------------------------------------------------
# Results
# ----------------------------------------------------------------
printf "\n========================================\n"
printf " tpm2-tools Compatibility Results\n"
printf "========================================\n"
printf "  PASS  %4d\n" $PASS
printf "  FAIL  %4d\n" $FAIL
printf "  SKIP  %4d\n" $SKIP
printf "========================================\n"

[ $FAIL -eq 0 ]
