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
VENDOR="${2:-nuvoton}"  # "nuvoton", "nations", or "nations-psk"
PASS=0 FAIL=0 TOTAL=0

# Nations PSK test data (from Vision/NSING reference PSK_DEMO_3)
# PSK: 64 bytes (used as IKM in HKDF-Extract during PSK_EXCHANGE)
NATIONS_PSK="dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047"
# ClearAuth: exactly 32 bytes (first 32 bytes of PSK per NSING convention)
# PSK_SET sends SHA-384(ClearAuth) as the 48-byte ClearAuthDigest
# PSK_CLEAR sends raw ClearAuth; TPM verifies SHA-384 match internally
NATIONS_CLEARAUTH="dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b933"

if [ -t 1 ]; then
    GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[0;33m' NC='\033[0m'
else
    GREEN='' RED='' YELLOW='' NC=''
fi

gpio_reset() {
    gpioset "$GPIO_CHIP" "$GPIO_PIN=0" 2>/dev/null
    sleep 0.1
    gpioset "$GPIO_CHIP" "$GPIO_PIN=1" 2>/dev/null
    sleep 2
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

if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found."
    echo "Usage: $0 [path-to-spdm_ctrl] [nuvoton|nations|nations-psk]"
    exit 1
fi

echo "=== SPDM Hardware Tests ($VENDOR) ==="
echo "Demo: $SPDM_DEMO  Caps: $CAPS_DEMO  Unit: $UNIT_TEST"
echo ""

if [ "$VENDOR" = "nuvoton" ]; then
    # Nuvoton test flow (identity key mode)
    run_test "SPDM status query" "$SPDM_DEMO" --status
    run_test "SPDM session connect" "$SPDM_DEMO" --connect
    run_test "Lock SPDM-only mode" "$SPDM_DEMO" --connect --lock

    if [ -x "$UNIT_TEST" ]; then
        run_test "Unit test over SPDM" "$UNIT_TEST"
    else
        echo -e "  ${YELLOW}Skipping: $UNIT_TEST not found${NC}"
    fi

    run_test "Unlock SPDM-only mode" "$SPDM_DEMO" --connect --unlock

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
    normalize_nations_chip
    trap 'normalize_nations_chip' EXIT

    run_test_no_reset "Unset identity key" "$SPDM_DEMO" --identity-key-unset
    run_test_no_reset "Set identity key" "$SPDM_DEMO" --identity-key-set
    run_test_no_reset "SPDM session connect" "$SPDM_DEMO" --connect
    run_test_no_reset "Status query" "$SPDM_DEMO" --status

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
    run_test_no_reset "Status (PSK provisioned)" "$SPDM_DEMO" --status

    # Step 4: PSK connect (VCA → PSK_EXCHANGE → PSK_FINISH)
    run_test_no_reset "PSK session connect" "$SPDM_DEMO" --psk "$NATIONS_PSK"

    # Step 5: PSK connect again (verify repeatable sessions)
    run_test_no_reset "PSK session connect (repeat)" "$SPDM_DEMO" --psk "$NATIONS_PSK"

    # Step 6: PSK_CLEAR (sends raw 32-byte ClearAuth, TPM verifies SHA-384)
    run_test_no_reset "PSK clear (PSK_CLEAR)" "$SPDM_DEMO" --psk-clear "$NATIONS_CLEARAUTH"

    # Step 7: Status check (should show PSK not provisioned)
    run_test_no_reset "Status (PSK cleared)" "$SPDM_DEMO" --status

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

else
    echo "Error: Unknown vendor '$VENDOR'. Use 'nuvoton', 'nations', or 'nations-psk'."
    exit 1
fi

echo ""
echo "=== Results: $TOTAL total, $PASS passed, $FAIL failed ==="
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"; exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"; exit 1
fi
