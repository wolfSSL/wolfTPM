#!/bin/bash
#
# spdm_test.sh - Full Nuvoton SPDM provisioning flow test
#
# Tests the complete SPDM lifecycle:
#   1. Connect + status (baseline)
#   2. Lock SPDM-only mode
#   3. TPM commands over SPDM (caps)
#   4. Unlock SPDM-only mode
#   5. Verify cleartext caps work again
#
# Usage: ./spdm_test.sh [path-to-spdm_demo]
#

SPDM_DEMO="${1:-./examples/spdm/spdm_demo}"
CAPS_DEMO="${2:-./examples/wrap/caps}"
GPIO_CHIP="gpiochip0"
GPIO_PIN="4"
PASS=0
FAIL=0
TOTAL=0

# Colors (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    NC='\033[0m'
else
    GREEN=''
    RED=''
    NC=''
fi

gpio_reset() {
    echo "  GPIO reset..."
    gpioset "$GPIO_CHIP" "$GPIO_PIN=0" 2>/dev/null
    sleep 0.1
    gpioset "$GPIO_CHIP" "$GPIO_PIN=1" 2>/dev/null
    sleep 2
}

run_test() {
    local name="$1"
    shift

    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    gpio_reset

    if "$@"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

# Check binaries exist
if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found or not executable"
    echo "Usage: $0 [path-to-spdm_demo] [path-to-caps]"
    exit 1
fi
if [ ! -x "$CAPS_DEMO" ]; then
    echo "Error: $CAPS_DEMO not found or not executable"
    echo "Usage: $0 [path-to-spdm_demo] [path-to-caps]"
    exit 1
fi

echo "=== Nuvoton SPDM Provisioning Flow Test ==="
echo "Using: $SPDM_DEMO"
echo "Caps:  $CAPS_DEMO"
echo ""

# Step 1: Connect + status (baseline, no SPDM-only)
run_test "Connect + Status" "$SPDM_DEMO" --connect --status

# Step 2: Lock SPDM-only mode
run_test "Connect + Lock SPDM-only" "$SPDM_DEMO" --connect --lock

# Step 3: TPM commands over SPDM (requires SPDM-only to be locked)
run_test "Connect + Caps over SPDM" "$SPDM_DEMO" --connect --caps

# Step 4: Unlock SPDM-only mode
run_test "Connect + Unlock SPDM-only" "$SPDM_DEMO" --connect --unlock

# Step 5: Verify cleartext TPM works (no SPDM, proves unlock worked)
run_test "Cleartext caps (no SPDM)" "$CAPS_DEMO"

# Summary
echo "=== Results ==="
echo "Total: $TOTAL  Passed: $PASS  Failed: $FAIL"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"
    exit 1
fi
