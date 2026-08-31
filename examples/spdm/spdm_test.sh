#!/bin/bash
# spdm_test.sh - SPDM hardware tests (Nuvoton / Nations Technology)
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

SPDM_DEMO="${1:-./examples/spdm/spdm_ctrl}"
CAPS_DEMO="./examples/wrap/caps"
UNIT_TEST="./tests/unit.test"
GPIO_CHIP="gpiochip0"
GPIO_PIN="4"
VENDOR="${2:-nuvoton}"  # nuvoton, nations, nations-psk, fwtpm-tcg, fwtpm-psk
FWTPM="${FWTPM:-./src/fwtpm/fwtpm_server}"
FWTPM_PORT="${FWTPM_PORT:-22321}"
FWTPM_PLAT_PORT="${FWTPM_PLAT_PORT:-22322}"
FWTPM_LOG="${FWTPM_LOG:-}"
FWTPM_LOG_CREATED=0
FWTPM_PID=""
SPDM_RESPONDER_PUBKEY="${SPDM_RESPONDER_PUBKEY:-}"
PASS=0 FAIL=0 TOTAL=0

# Nations PSK test data (from Vision/NSING reference PSK_DEMO_3)
# PSK: 64 bytes (used as IKM in HKDF-Extract during PSK_EXCHANGE)
NATIONS_PSK="dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047"
# ClearAuth: exactly 32 bytes (first 32 bytes of PSK per NSING convention)
# PSK_SET sends SHA-384(ClearAuth) as the 48-byte ClearAuthDigest
# PSK_CLEAR sends raw ClearAuth; TPM verifies SHA-384 match internally
NATIONS_CLEARAUTH="dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b933"
TEST_RESPONDER_PUBKEY="${NATIONS_CLEARAUTH}${NATIONS_CLEARAUTH}${NATIONS_CLEARAUTH}"

if [ -t 1 ]; then
    GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[0;33m' NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

# fwtpm modes route TPM/SPDM traffic over the swtpm socket. No GPIO line,
# no NV provisioning persistence - the responder is started fresh per run.
is_fwtpm_mode() {
    [ "$VENDOR" = "fwtpm-tcg" ] || [ "$VENDOR" = "fwtpm-psk" ]
}

valid_responder_pubkey() {
    [ "${#SPDM_RESPONDER_PUBKEY}" -eq 192 ] &&
        [[ "$SPDM_RESPONDER_PUBKEY" =~ ^[[:xdigit:]]+$ ]]
}

require_responder_pubkey() {
    if ! valid_responder_pubkey; then
        echo "Error: identity mode requires SPDM_RESPONDER_PUBKEY."
        echo "Set it to the trusted 192-character P-384 X||Y key."
        return 1
    fi
}

# Invoked indirectly by run_test and run_test_no_reset.
# shellcheck disable=SC2329
run_identity() {
    # Leave Nations unforced so a dual-vendor build exercises DID/VID AUTO
    # selection and the resulting vendor-specific command dispatch.
    if [ "$VENDOR" = "nations" ]; then
        "$SPDM_DEMO" --responder-pubkey "$SPDM_RESPONDER_PUBKEY" "$@"
    else
        "$SPDM_DEMO" --vendor=nuvoton \
            --responder-pubkey "$SPDM_RESPONDER_PUBKEY" "$@"
    fi
}

# Invoked indirectly by run_test while identity mode is locked.
# shellcheck disable=SC2329
run_unit_with_pin() {
    local identity_vendor=nuvoton

    if [ "$VENDOR" = "nations" ]; then
        identity_vendor=nations
    fi
    SPDM_RESPONDER_PUBKEY="$SPDM_RESPONDER_PUBKEY" \
        SPDM_IDENTITY_VENDOR="$identity_vendor" \
        WOLFTPM_TEST_SPDM_ONLY=1 "$UNIT_TEST"
}

# Invoked indirectly by run_test in the fwTPM PSK flow.
# shellcheck disable=SC2329
run_unit_with_psk() {
    WOLFTPM_TEST_SPDM_PSK="$NATIONS_PSK" "$UNIT_TEST"
}

gpio_reset() {
    if is_fwtpm_mode; then
        return 0
    fi
    gpioset "$GPIO_CHIP" "$GPIO_PIN=0" 2>/dev/null
    sleep 0.1
    gpioset "$GPIO_CHIP" "$GPIO_PIN=1" 2>/dev/null
    sleep 2
}

fwtpm_start() {
    local mode="$1"
    local attempt
    if [ -z "$FWTPM_LOG" ]; then
        FWTPM_LOG=$(mktemp "/tmp/fwtpm_spdm_test.XXXXXX") ||
            return 1
        FWTPM_LOG_CREATED=1
    fi
    rm -f fwtpm_nv.bin NVChip 2>/dev/null
    if [ "$mode" = "psk" ]; then
        "$FWTPM" --spdm-psk --spdm-psk-hex "$NATIONS_PSK" \
            --port "$FWTPM_PORT" --platform-port "$FWTPM_PLAT_PORT" \
            --clear > "$FWTPM_LOG" 2>&1 &
    else
        "$FWTPM" --spdm-tcg --port "$FWTPM_PORT" \
            --platform-port "$FWTPM_PLAT_PORT" --clear \
            > "$FWTPM_LOG" 2>&1 &
    fi
    FWTPM_PID=$!
    for ((attempt = 0; attempt < 50; attempt++)); do
        if [ "$mode" = "tcg" ]; then
            SPDM_RESPONDER_PUBKEY=$(sed -n \
                '/^  SPDM responder public key: /{s///;p;q;}' "$FWTPM_LOG")
        fi
        if grep -q '^fwTPM: Listening on command port' "$FWTPM_LOG" &&
            { [ "$mode" != "tcg" ] || valid_responder_pubkey; }; then
            break
        fi
        if ! kill -0 "$FWTPM_PID" 2>/dev/null; then
            echo "Error: fwTPM exited during startup. Log: $FWTPM_LOG"
            sed -n '1,120p' "$FWTPM_LOG"
            return 1
        fi
        sleep 0.1
    done
    if ! grep -q '^fwTPM: Listening on command port' "$FWTPM_LOG"; then
        echo "Error: fwTPM did not become ready. Log: $FWTPM_LOG"
        return 1
    fi
    if [ "$mode" = "tcg" ] && ! valid_responder_pubkey; then
        echo "Error: fwTPM did not publish its responder key."
        echo "Log: $FWTPM_LOG"
        return 1
    fi
    export TPM2_SWTPM_HOST=127.0.0.1
    export TPM2_SWTPM_PORT="$FWTPM_PORT"
}

# Invoked by the EXIT trap in fwTPM modes.
# shellcheck disable=SC2329
fwtpm_stop() {
    if [ -n "$FWTPM_PID" ]; then
        kill "$FWTPM_PID" 2>/dev/null || true
        wait "$FWTPM_PID" 2>/dev/null || true
        FWTPM_PID=""
    fi
    if [ "$FWTPM_LOG_CREATED" -eq 1 ] && [ "$FAIL" -eq 0 ] &&
        [ "$TOTAL" -gt 0 ]; then
        rm -f -- "$FWTPM_LOG"
        FWTPM_LOG=""
    fi
}

# normalize_nations_chip: bring NS350 to canonical clean state
# (identity-key=1, no PSK). Idempotent — safe to call multiple times.
# NS350 IdentityKeySet returns TPM_RC_VALUE when setting to current value,
# so "already in target state" is indistinguishable from real errors; we
# probe by trying both transitions rather than trusting a single call.
normalize_nations_chip() {
    echo "--- Normalizing NS350 to clean state (identity-key=1, no PSK) ---"
    gpio_reset
    # Clear PSK if set. PSKNotSet (0xffA3) means already clean — that's fine.
    # Any other failure is also non-fatal here; the identity-key-set below
    # will surface the real problem if state is unrecoverable.
    "$SPDM_DEMO" --psk-clear "$NATIONS_CLEARAUTH" >/dev/null 2>&1 || true
    # Now try to set identity key. Succeeds if at 0, benign-fails with
    # TPM_RC_VALUE if already at 1. Either outcome = state is 1.
    "$SPDM_DEMO" --identity-key-set >/dev/null 2>&1 || true
    echo "--- Normalization complete ---"
    echo ""
}

run_test() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    gpio_reset
    if "$@"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

# run_test_caps: caps returns number of persistent handles as exit code, not 0
run_test_caps() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    gpio_reset
    if "$@" 2>&1 | grep -q "caps read successfully"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_test_caps_no_reset() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    if "$@" 2>&1 | grep -q "caps read successfully"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

# run_test_no_reset: Same as run_test but skip GPIO reset (for back-to-back commands)
run_test_no_reset() {
    local name="$1"; shift
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    if "$@"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_test_output() {
    local name="$1"; local expected="$2"; shift 2
    local output result
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    gpio_reset
    output=$("$@" 2>&1)
    result=$?
    printf '%s\n' "$output"
    if [ "$result" -eq 0 ] && grep -Fq -- "$expected" <<< "$output"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_test_output_no_reset() {
    local name="$1"; local expected="$2"; shift 2
    local output result
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    output=$("$@" 2>&1)
    result=$?
    printf '%s\n' "$output"
    if [ "$result" -eq 0 ] && grep -Fq -- "$expected" <<< "$output"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

run_test_rejected() {
    local name="$1"; local expected="$2"; shift 2
    local output result
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    gpio_reset
    output=$("$@" 2>&1)
    result=$?
    printf '%s\n' "$output"
    if [ "$result" -ne 0 ] && grep -Fq -- "$expected" <<< "$output"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found."
    echo "Usage: $0 [path-to-spdm_ctrl] [nuvoton|nations|nations-psk|fwtpm-tcg|fwtpm-psk]"
    exit 1
fi

echo "=== SPDM Hardware Tests ($VENDOR) ==="
echo "Demo: $SPDM_DEMO  Caps: $CAPS_DEMO  Unit: $UNIT_TEST"
echo ""

if [ "$VENDOR" = "nuvoton" ]; then
    # Nuvoton test flow (identity key mode)
    require_responder_pubkey || exit 1
    run_test_output "Pinned-key initialization establishes SPDM" \
        "Already connected" run_identity --connect
    run_test "SPDM status query" "$SPDM_DEMO" --status
    run_test "Lock SPDM-only mode" run_identity --connect --lock
    run_test_rejected "Unpinned initialization rejected while locked" \
        "Invalid state" "$SPDM_DEMO" --status
    if [ -x "$UNIT_TEST" ]; then
        run_test "Unit test over pinned SPDM" run_unit_with_pin
    else
        echo -e "  ${YELLOW}Skipping: $UNIT_TEST not found${NC}"
    fi
    run_test "Status in SPDM-only mode" run_identity --status
    run_test "TPM capabilities in SPDM-only mode" run_identity --caps
    run_test "Unlock SPDM-only mode" run_identity --connect --unlock

    if [ -x "$CAPS_DEMO" ]; then
        run_test_caps "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
    fi

elif [ "$VENDOR" = "nations" ]; then
    # Nations NS350 identity key mode — full lifecycle test
    # GPIO 4 is wired to TPM_RST on NS350 and clears volatile state, but
    # identity-key/PSK are NV-persistent across reset. The entry/exit
    # normalization ensures the chip is always at a known starting state
    # and always left clean, regardless of prior runs or mid-test failures.
    require_responder_pubkey || exit 1
    normalize_nations_chip
    trap 'normalize_nations_chip' EXIT

    run_test_no_reset "Unset identity key" "$SPDM_DEMO" --identity-key-unset
    run_test_no_reset "Set identity key" "$SPDM_DEMO" --identity-key-set
    run_test_no_reset "SPDM session connect" run_identity --connect
    run_test_no_reset "AUTO Nations status/lock/unlock dispatch" run_identity \
        --status --lock --unlock

    if [ -x "$CAPS_DEMO" ]; then
        run_test_caps_no_reset "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
    fi

elif [ "$VENDOR" = "nations-psk" ]; then
    # Nations NS350 PSK mode — full lifecycle test
    #
    # PSK and identity key are mutually exclusive on NS350.
    # Flow: unset identity key → PSK_SET → PSK connect → status →
    #       PSK_CLEAR → re-provision → re-connect → final clear →
    #       restore identity key → cleartext caps
    #
    # Uses NSING reference test data (PSK_DEMO_3 from Vision's traces).
    # ClearAuth is always exactly 32 bytes per TCG spec.

    # Entry/exit normalization: always start clean (identity-key=1, no PSK)
    # and always end clean, regardless of prior state or mid-test failures.
    normalize_nations_chip
    trap 'normalize_nations_chip' EXIT

    # Step 1: Ensure identity key is unset (required for PSK mode)
    run_test_no_reset "Unset identity key" "$SPDM_DEMO" --identity-key-unset

    # Step 2: Provision PSK (PSK_SET_ vendor command)
    # Sends PSK(64) + SHA-384(ClearAuth)(48) = 112 bytes
    run_test_no_reset "PSK provision (PSK_SET)" "$SPDM_DEMO" --psk-set "$NATIONS_PSK" "$NATIONS_CLEARAUTH"

    # Step 3: Status check (should show PSK provisioned)
    run_test_output_no_reset "Status (PSK provisioned)" "PSK: provisioned" \
        "$SPDM_DEMO" --status

    # Step 4: PSK connect (VCA → PSK_EXCHANGE → PSK_FINISH)
    run_test_no_reset "PSK session connect" "$SPDM_DEMO" --psk "$NATIONS_PSK"

    # Step 5: PSK connect again (verify repeatable sessions)
    run_test_no_reset "PSK session connect (repeat)" "$SPDM_DEMO" --psk "$NATIONS_PSK"

    # Step 6: PSK_CLEAR (sends raw 32-byte ClearAuth, TPM verifies SHA-384)
    run_test_no_reset "PSK clear (PSK_CLEAR)" "$SPDM_DEMO" --psk-clear "$NATIONS_CLEARAUTH"

    # Step 7: Status check (should show PSK not provisioned)
    run_test_output_no_reset "Status (PSK cleared)" \
        "PSK: not provisioned" "$SPDM_DEMO" --status

    # Step 8: Re-provision PSK (verify PSK_SET works after clear)
    run_test_no_reset "PSK re-provision (PSK_SET)" "$SPDM_DEMO" --psk-set "$NATIONS_PSK" "$NATIONS_CLEARAUTH"

    # Step 9: PSK connect after re-provision
    run_test_no_reset "PSK session connect (after re-provision)" "$SPDM_DEMO" --psk "$NATIONS_PSK"

    # Step 10: Final PSK_CLEAR (leave module in clean state)
    run_test_no_reset "Final PSK clear" "$SPDM_DEMO" --psk-clear "$NATIONS_CLEARAUTH"

    # Step 11: Restore identity key (factory default)
    run_test_no_reset "Restore identity key" "$SPDM_DEMO" --identity-key-set

    # Step 12: Cleartext TPM commands (verify module works normally)
    if [ -x "$CAPS_DEMO" ]; then
        run_test_caps_no_reset "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
    fi

elif [ "$VENDOR" = "fwtpm-tcg" ]; then
    # fwtpm in TCG cert mode - mirrors the Nuvoton sequence against
    # the software responder. Lock/unlock toggles the SPDMONLY runtime
    # state in the responder; while locked, plaintext TPM frames are
    # rejected with TPM_RC_DISABLED.
    if [ ! -x "$FWTPM" ]; then
        echo "Error: $FWTPM not found"
        exit 1
    fi
    trap 'fwtpm_stop' EXIT
    if ! fwtpm_start tcg; then
        exit 1
    fi

    run_test_rejected "Unknown vendor is rejected" \
        "Unknown --vendor= value" "$SPDM_DEMO" --vendor=unknown --status
    run_test_rejected "Responder key operand is required" \
        "--responder-pubkey requires 192 hex characters" "$SPDM_DEMO" \
        --responder-pubkey --status
    run_test_rejected "Malformed responder key is rejected" \
        "Invalid responder public key" "$SPDM_DEMO" \
        --responder-pubkey 00 --status
    run_test_rejected "AUTO rejects an unrecognized TPM vendor" \
        "Invalid state" "$SPDM_DEMO" \
        --responder-pubkey "$SPDM_RESPONDER_PUBKEY" --connect
    run_test_output "Pinned-key initialization establishes SPDM" \
        "Already connected" run_identity --connect
    run_test "SPDM status query" "$SPDM_DEMO" --status
    run_test "Lock SPDM-only mode" run_identity --connect --lock
    run_test_rejected "Unpinned initialization rejected while locked" \
        "Invalid state" "$SPDM_DEMO" --status
    if [ -x "$UNIT_TEST" ]; then
        run_test "Unit test over pinned SPDM" run_unit_with_pin
    else
        echo -e "  ${YELLOW}Skipping: $UNIT_TEST not found${NC}"
    fi
    run_test "Status in SPDM-only mode" run_identity --status
    run_test "TPM capabilities in SPDM-only mode" run_identity --caps
    run_test "Unlock SPDM-only mode" run_identity --connect --unlock

    if [ -x "$CAPS_DEMO" ]; then
        run_test_caps "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
    fi

elif [ "$VENDOR" = "fwtpm-psk" ]; then
    # fwtpm in PSK mode - mirrors the Nations-PSK 12-test sequence, minus
    # the two identity-key steps. IDENTITY_KEY_SET/UNSET are Nations
    # TPM2 vendor commands (TPM_CC_Nations_IdentityKeySet) that write to
    # vendor NV; they don't apply to a software TPM.
    if [ ! -x "$FWTPM" ]; then
        echo "Error: $FWTPM not found"
        exit 1
    fi
    trap 'fwtpm_stop' EXIT
    if ! fwtpm_start psk; then
        exit 1
    fi

    run_test_rejected "PSK operand is required" \
        "--psk requires a hexadecimal key" "$SPDM_DEMO" --psk --status
    run_test_rejected "Malformed PSK is rejected" \
        "Invalid PSK hex string" "$SPDM_DEMO" --psk zz --status
    run_test_rejected "Responder key and PSK are mutually exclusive" \
        "Choose either --responder-pubkey or --psk" "$SPDM_DEMO" \
        --vendor=nations --responder-pubkey "$TEST_RESPONDER_PUBKEY" \
        --psk "$NATIONS_PSK"
    run_test_rejected "PSK rejects an explicit Nuvoton vendor (vendor first)" \
        "PSK sessions require --vendor=nations" "$SPDM_DEMO" \
        --vendor=nuvoton --psk "$NATIONS_PSK"
    run_test_rejected "PSK rejects an explicit Nuvoton vendor (PSK first)" \
        "PSK sessions require --vendor=nations" "$SPDM_DEMO" \
        --psk "$NATIONS_PSK" --vendor=nuvoton
    run_test_rejected \
        "Nations PSK clear rejects an explicit Nuvoton vendor (vendor first)" \
        "Nations-only commands require --vendor=nations" "$SPDM_DEMO" \
        --vendor=nuvoton --psk-clear "$NATIONS_CLEARAUTH"
    run_test_rejected \
        "Nations PSK set rejects an explicit Nuvoton vendor (command first)" \
        "Nations-only commands require --vendor=nations" "$SPDM_DEMO" \
        --psk-set "$NATIONS_PSK" "$NATIONS_CLEARAUTH" --vendor=nuvoton
    run_test_rejected "PSK clear operand is not re-parsed as --psk" \
        "Nations-only commands require --vendor=nations" "$SPDM_DEMO" \
        --vendor=nuvoton --psk-clear --psk
    run_test_rejected "PSK clear requires its ClearAuth operand" \
        "--psk-clear requires a ClearAuth hex argument" "$SPDM_DEMO" \
        --psk-clear --status
    run_test_rejected "PSK set requires both operands" \
        "--psk-set requires PSK and ClearAuth hex arguments" "$SPDM_DEMO" \
        --psk-set AABB --status
    run_test "PSK provision (PSK_SET)" "$SPDM_DEMO" --vendor=nations \
        --psk-set "$NATIONS_PSK" "$NATIONS_CLEARAUTH"
    run_test_output "Status (PSK provisioned)" "PSK: provisioned" \
        "$SPDM_DEMO" --vendor=nations --status
    run_test_output "PSK initialization establishes SPDM" \
        "Already connected" "$SPDM_DEMO" --vendor=nations \
        --psk "$NATIONS_PSK"
    if [ -x "$UNIT_TEST" ]; then
        run_test "Unit test exercises PSK initialization" run_unit_with_psk
    else
        echo -e "  ${YELLOW}Skipping: $UNIT_TEST not found${NC}"
    fi
    run_test "Lock PSK SPDM-only mode" "$SPDM_DEMO" --vendor=nations \
        --psk "$NATIONS_PSK" --lock
    run_test_rejected "Uncredentialed initialization rejected while locked" \
        "Invalid state" "$SPDM_DEMO" --vendor=nations --status
    run_test_output "PSK status in SPDM-only mode" \
        "PSK: provisioned  SPDM-Only: ENABLED" "$SPDM_DEMO" \
        --vendor=nations --psk "$NATIONS_PSK" --status
    run_test_output "Status preserves the PSK session for TPM commands" \
        "Session: active" "$SPDM_DEMO" --vendor=nations \
        --psk "$NATIONS_PSK" --status --caps
    run_test "Unlock PSK SPDM-only mode" "$SPDM_DEMO" --vendor=nations \
        --psk "$NATIONS_PSK" --unlock
    run_test "PSK clear (PSK_CLEAR)" "$SPDM_DEMO" --vendor=nations \
        --psk-clear "$NATIONS_CLEARAUTH"
    run_test_output "Status (PSK cleared)" "PSK: not provisioned" \
        "$SPDM_DEMO" --vendor=nations --status
    run_test "PSK re-provision (PSK_SET)" "$SPDM_DEMO" --vendor=nations \
        --psk-set "$NATIONS_PSK" "$NATIONS_CLEARAUTH"
    run_test "PSK session connect (after re-provision)" "$SPDM_DEMO" \
        --vendor=nations --psk "$NATIONS_PSK"
    run_test "Final PSK clear" "$SPDM_DEMO" --vendor=nations \
        --psk-clear "$NATIONS_CLEARAUTH"

    if [ -x "$CAPS_DEMO" ]; then
        run_test_caps "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
    fi

else
    echo "Error: Unknown vendor '$VENDOR'."
    echo "Valid: nuvoton, nations, nations-psk, fwtpm-tcg, fwtpm-psk"
    exit 1
fi

echo ""
echo "=== Results: $TOTAL total, $PASS passed, $FAIL failed ==="
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"; exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"; exit 1
fi
