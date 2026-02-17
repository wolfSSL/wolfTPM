#!/bin/bash
#
# spdm_test.sh - SPDM test script
#
# Supports two modes:
#   --emu      Test SPDM with libspdm emulator (session + measurements)
#   --nuvoton  Test Nuvoton SPDM provisioning flow (lock/unlock/caps)
#
# Usage:
#   ./spdm_test.sh --emu                  # Emulator tests
#   ./spdm_test.sh --nuvoton              # Nuvoton hardware tests
#   ./spdm_test.sh --emu --nuvoton        # Both
#   ./spdm_test.sh                        # Default: --nuvoton
#

SPDM_DEMO="./examples/spdm/spdm_demo"
CAPS_DEMO="./examples/wrap/caps"
GPIO_CHIP="gpiochip0"
GPIO_PIN="4"
PASS=0
FAIL=0
TOTAL=0
DO_EMU=0
DO_NUVOTON=0
EMU_PID=""

# Colors (if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

usage() {
    echo "Usage: $0 [--emu] [--nuvoton] [path-to-spdm_demo]"
    echo ""
    echo "Options:"
    echo "  --emu       Test SPDM with libspdm emulator (session + measurements)"
    echo "  --nuvoton   Test Nuvoton SPDM provisioning flow (lock/unlock/caps)"
    echo "  -h, --help  Show this help"
    echo ""
    echo "If neither --emu nor --nuvoton is specified, defaults to --nuvoton."
    echo ""
    echo "Emulator mode expects spdm_responder_emu to be found via:"
    echo "  1. SPDM_EMU_PATH environment variable"
    echo "  2. ../spdm-emu/build/bin/ (cloned next to wolfTPM)"
    echo "  3. spdm_responder_emu in PATH"
}

# Parse arguments
for arg in "$@"; do
    case "$arg" in
        --emu)
            DO_EMU=1
            ;;
        --nuvoton)
            DO_NUVOTON=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            # Treat as path to spdm_demo
            SPDM_DEMO="$arg"
            ;;
    esac
done

# Default to --nuvoton if nothing specified
if [ $DO_EMU -eq 0 ] && [ $DO_NUVOTON -eq 0 ]; then
    DO_NUVOTON=1
fi

# Find spdm_responder_emu for --emu mode
find_emu() {
    # 1. Check SPDM_EMU_PATH
    if [ -n "$SPDM_EMU_PATH" ]; then
        if [ -x "$SPDM_EMU_PATH/spdm_responder_emu" ]; then
            EMU_DIR="$SPDM_EMU_PATH"
            EMU_BIN="$SPDM_EMU_PATH/spdm_responder_emu"
            return 0
        elif [ -x "$SPDM_EMU_PATH" ]; then
            EMU_DIR="$(dirname "$SPDM_EMU_PATH")"
            EMU_BIN="$SPDM_EMU_PATH"
            return 0
        fi
    fi

    # 2. Check common relative paths (cloned next to wolfTPM)
    for dir in \
        "../spdm-emu/build/bin" \
        "../../spdm-emu/build/bin" \
        "$HOME/spdm-emu/build/bin"; do
        if [ -x "$dir/spdm_responder_emu" ]; then
            EMU_DIR="$dir"
            EMU_BIN="$dir/spdm_responder_emu"
            return 0
        fi
    done

    # 3. Check PATH
    if command -v spdm_responder_emu >/dev/null 2>&1; then
        EMU_BIN="$(command -v spdm_responder_emu)"
        EMU_DIR="$(dirname "$EMU_BIN")"
        return 0
    fi

    return 1
}

# Start the emulator (must run from its bin dir for cert files)
start_emu() {
    echo "  Starting spdm_responder_emu..."
    (cd "$EMU_DIR" && ./spdm_responder_emu --ver 1.2 \
        --hash SHA_384 --asym ECDSA_P384 \
        --dhe SECP_384_R1 --aead AES_256_GCM >/dev/null 2>&1) &
    EMU_PID=$!
    sleep 1

    # Verify it started
    if ! kill -0 "$EMU_PID" 2>/dev/null; then
        echo -e "  ${RED}ERROR: Emulator failed to start${NC}"
        EMU_PID=""
        return 1
    fi
    return 0
}

# Stop the emulator
stop_emu() {
    if [ -n "$EMU_PID" ]; then
        kill "$EMU_PID" 2>/dev/null
        wait "$EMU_PID" 2>/dev/null
        EMU_PID=""
    fi
}

# Cleanup on exit
cleanup() {
    stop_emu
}
trap cleanup EXIT

gpio_reset() {
    echo "  GPIO reset..."
    gpioset "$GPIO_CHIP" "$GPIO_PIN=0" 2>/dev/null
    sleep 0.1
    gpioset "$GPIO_CHIP" "$GPIO_PIN=1" 2>/dev/null
    sleep 2
}

# Run a test with GPIO reset (Nuvoton hardware)
run_test_nuvoton() {
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

# Run an emulator test (starts/stops emu per test since it's single-shot)
run_test_emu() {
    local name="$1"
    shift

    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"

    if ! start_emu; then
        echo -e "  ${RED}FAIL (emulator start)${NC}"
        FAIL=$((FAIL + 1))
        echo ""
        return 1
    fi

    if "$@"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi

    stop_emu
    sleep 1  # Let port release
    echo ""
}

# Check spdm_demo exists
if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found or not executable"
    usage
    exit 1
fi

# ==========================================================================
# Emulator Tests
# ==========================================================================
if [ $DO_EMU -eq 1 ]; then
    echo "=== SPDM Emulator Tests ==="

    if ! find_emu; then
        echo -e "${RED}ERROR: spdm_responder_emu not found${NC}"
        echo ""
        echo "Set SPDM_EMU_PATH or clone spdm-emu next to wolfTPM:"
        echo "  git clone https://github.com/DMTF/spdm-emu.git ../spdm-emu"
        echo "  cd ../spdm-emu && mkdir build && cd build"
        echo "  cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls .."
        echo "  make copy_sample_key && make"
        exit 1
    fi

    echo "Using emulator: $EMU_BIN"
    echo "Using demo:     $SPDM_DEMO"
    echo ""

    # Test 1: Session establishment
    run_test_emu "Session establishment (--emu)" \
        "$SPDM_DEMO" --emu

    # Test 2: Session + signed measurements
    run_test_emu "Signed measurements (--meas)" \
        "$SPDM_DEMO" --meas

    # Test 3: Session + unsigned measurements
    run_test_emu "Unsigned measurements (--meas --no-sig)" \
        "$SPDM_DEMO" --meas --no-sig

    # Test 4: Challenge authentication (sessionless)
    run_test_emu "Challenge authentication (--challenge)" \
        "$SPDM_DEMO" --challenge

    # Test 5: Session + heartbeat
    run_test_emu "Heartbeat (--emu --heartbeat)" \
        "$SPDM_DEMO" --emu --heartbeat

    # Test 6: Session + key update
    run_test_emu "Key update (--emu --key-update)" \
        "$SPDM_DEMO" --emu --key-update

    echo ""
fi

# ==========================================================================
# Nuvoton Hardware Tests
# ==========================================================================
if [ $DO_NUVOTON -eq 1 ]; then
    echo "=== Nuvoton SPDM Provisioning Flow Test ==="
    echo "Using: $SPDM_DEMO"
    echo "Caps:  $CAPS_DEMO"
    echo ""

    if [ ! -x "$CAPS_DEMO" ]; then
        echo -e "${YELLOW}Warning: $CAPS_DEMO not found, skipping cleartext test${NC}"
    fi

    # Step 1: Connect + status (baseline, no SPDM-only)
    run_test_nuvoton "Connect + Status" "$SPDM_DEMO" --connect --status

    # Step 2: Lock SPDM-only mode
    run_test_nuvoton "Connect + Lock SPDM-only" "$SPDM_DEMO" --connect --lock

    # Step 3: TPM commands over SPDM (requires SPDM-only to be locked)
    run_test_nuvoton "Connect + Caps over SPDM" "$SPDM_DEMO" --connect --caps

    # Step 4: Unlock SPDM-only mode
    run_test_nuvoton "Connect + Unlock SPDM-only" "$SPDM_DEMO" --connect --unlock

    # Step 5: Verify cleartext TPM works (no SPDM, proves unlock worked)
    if [ -x "$CAPS_DEMO" ]; then
        run_test_nuvoton "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    fi

    echo ""
fi

# ==========================================================================
# Summary
# ==========================================================================
echo "=== Results ==="
echo "Total: $TOTAL  Passed: $PASS  Failed: $FAIL"
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"
    exit 1
fi
