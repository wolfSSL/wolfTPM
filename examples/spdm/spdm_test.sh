#!/bin/bash
#
# spdm_test.sh - SPDM test script
#
# Supports two modes:
#   --emu      Test SPDM with libspdm emulator (session + measurements)
#   --nuvoton  Test Nuvoton SPDM hardware (lock, unit test over SPDM, unlock)
#
# Usage:
#   ./spdm_test.sh --emu                  # Emulator tests
#   ./spdm_test.sh --nuvoton              # Nuvoton hardware tests
#   ./spdm_test.sh --emu --nuvoton        # Both
#   ./spdm_test.sh                        # Default: --nuvoton
#

SPDM_DEMO="./examples/spdm/spdm_demo"
CAPS_DEMO="./examples/wrap/caps"
UNIT_TEST="./tests/unit.test"
GPIO_CHIP="gpiochip0"
GPIO_PIN="4"
PASS=0
FAIL=0
TOTAL=0
DO_EMU=0
DO_NUVOTON=0
EMU_PID=""
EMU_LOG="/tmp/spdm_emu_$$.log"

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
    echo "  --nuvoton   Test Nuvoton SPDM hardware (lock, unit test over SPDM, unlock)"
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

    # Kill any stale emulator processes
    if pgrep -x spdm_responder_emu >/dev/null 2>&1; then
        echo "  Killing stale emulator process..."
        pkill -9 -x spdm_responder_emu 2>/dev/null
        sleep 2
    fi

    # Check port availability
    if ss -tlnp 2>/dev/null | grep -q ":2323 "; then
        echo -e "  ${RED}ERROR: Port 2323 already in use${NC}"
        ss -tlnp 2>/dev/null | grep ":2323 "
        return 1
    fi

    # Verify cert/key files exist in EMU_DIR
    if [ ! -f "$EMU_DIR/EcP384/end_responder.cert" ] && \
       [ ! -d "$EMU_DIR/EcP384" ]; then
        echo -e "  ${YELLOW}WARNING: Certificate files may be missing in $EMU_DIR${NC}"
        echo "  Run 'make copy_sample_key' in the spdm-emu build directory"
    fi

    (cd "$EMU_DIR" && ./spdm_responder_emu --ver 1.2 \
        --hash SHA_384 --asym ECDSA_P384 \
        --dhe SECP_384_R1 --aead AES_256_GCM >"$EMU_LOG" 2>&1) &
    EMU_PID=$!
    sleep 2

    # Verify it started
    if ! kill -0 "$EMU_PID" 2>/dev/null; then
        echo -e "  ${RED}ERROR: Emulator failed to start${NC}"
        if [ -s "$EMU_LOG" ]; then
            echo "  Emulator output:"
            sed 's/^/    /' "$EMU_LOG" | head -20
        fi
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
    rm -f "$EMU_LOG"
}
trap cleanup EXIT

gpio_reset() {
    echo "  GPIO reset..."
    gpioset "$GPIO_CHIP" "$GPIO_PIN=0" 2>/dev/null
    sleep 0.1
    gpioset "$GPIO_CHIP" "$GPIO_PIN=1" 2>/dev/null
    sleep 2
}

# Run a test with optional setup/teardown
# Usage: run_test <mode> <name> <command...>
#   mode: "nuvoton" (GPIO reset before) or "emu" (start/stop emulator around)
run_test() {
    local mode="$1"
    local name="$2"
    shift 2

    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"

    # Pre-test setup
    if [ "$mode" = "nuvoton" ]; then
        gpio_reset
    elif [ "$mode" = "emu" ]; then
        if ! start_emu; then
            echo -e "  ${RED}FAIL (emulator start)${NC}"
            FAIL=$((FAIL + 1))
            echo ""
            return 1
        fi
    fi

    if "$@"; then
        echo -e "  ${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi

    # Post-test teardown
    if [ "$mode" = "emu" ]; then
        stop_emu
        sleep 1  # Let port release
    fi
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
    run_test emu "Session establishment (--emu)" \
        "$SPDM_DEMO" --emu

    # Test 2: Session + signed measurements
    run_test emu "Signed measurements (--meas)" \
        "$SPDM_DEMO" --meas

    # Test 3: Session + unsigned measurements
    run_test emu "Unsigned measurements (--meas --no-sig)" \
        "$SPDM_DEMO" --meas --no-sig

    # Test 4: Challenge authentication (sessionless)
    run_test emu "Challenge authentication (--challenge)" \
        "$SPDM_DEMO" --challenge

    # Test 5: Session + heartbeat
    run_test emu "Heartbeat (--emu --heartbeat)" \
        "$SPDM_DEMO" --emu --heartbeat

    # Test 6: Session + key update
    run_test emu "Key update (--emu --key-update)" \
        "$SPDM_DEMO" --emu --key-update

    echo ""
fi

# ==========================================================================
# Nuvoton Hardware Tests
# ==========================================================================
if [ $DO_NUVOTON -eq 1 ]; then
    echo "=== Nuvoton SPDM Hardware Tests ==="
    echo "Demo:      $SPDM_DEMO"
    echo "Caps:      $CAPS_DEMO"
    echo "Unit test: $UNIT_TEST"
    echo ""

    # Step 1: SPDM status query (vendor command over TIS)
    run_test nuvoton "SPDM status query" "$SPDM_DEMO" --status

    # Step 2: SPDM session establishment (version + keygen + handshake)
    run_test nuvoton "SPDM session connect" "$SPDM_DEMO" --connect

    # Step 3: Lock SPDM-only mode (connect + lock in one session)
    run_test nuvoton "Lock SPDM-only mode" "$SPDM_DEMO" --connect --lock

    # Step 4: Unit test over SPDM (auto-detects SPDM-only, all commands encrypted)
    if [ -x "$UNIT_TEST" ]; then
        run_test nuvoton "Unit test over SPDM" "$UNIT_TEST"
    else
        echo -e "  ${YELLOW}Skipping: $UNIT_TEST not found${NC}"
    fi

    # Step 5: Unlock SPDM-only mode
    run_test nuvoton "Unlock SPDM-only mode" "$SPDM_DEMO" --connect --unlock

    # Step 6: Verify cleartext TPM works (proves unlock succeeded)
    if [ -x "$CAPS_DEMO" ]; then
        run_test nuvoton "Cleartext caps (no SPDM)" "$CAPS_DEMO"
    else
        echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
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
