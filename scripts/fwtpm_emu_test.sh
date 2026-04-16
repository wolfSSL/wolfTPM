#!/bin/bash
#
# fwTPM Emulator Test Script
#
# Builds the fwTPM STM32 port in self-test mode and runs it in the
# m33mu Cortex-M33 emulator. Tests: Startup, SelfTest, GetRandom,
# GetCapability. Exit code 0 = pass, non-zero = fail.
#
# Usage:
#   scripts/fwtpm_emu_test.sh [--no-build] [--tzen]
#
# Requires:
#   - arm-none-eabi-gcc toolchain
#   - m33mu emulator (https://github.com/danielinux/m33mu)
#   - wolfSSL source at WOLFSSL_DIR (default: /tmp/wolfssl-fwtpm)
#
# Environment:
#   M33MU       Path to m33mu binary (default: auto-detect)
#   WOLFSSL_DIR Path to wolfSSL source (default: /tmp/wolfssl-fwtpm)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WOLFTPM_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# STM32 port lives in wolftpm-examples repo
if [ -n "$WOLFTPM_EXAMPLES_DIR" ]; then
    PORT_DIR="$WOLFTPM_EXAMPLES_DIR/STM32/fwtpm-stm32h5"
elif [ -d "$WOLFTPM_DIR/../wolftpm-examples/STM32/fwtpm-stm32h5" ]; then
    PORT_DIR="$(cd "$WOLFTPM_DIR/../wolftpm-examples/STM32/fwtpm-stm32h5" && pwd)"
else
    echo "ERROR: wolftpm-examples not found. Set WOLFTPM_EXAMPLES_DIR or clone"
    echo "       https://github.com/wolfSSL/wolftpm-examples alongside wolftpm."
    exit 1
fi

DO_BUILD=1
TZEN=0

for arg in "$@"; do
    case "$arg" in
        --no-build) DO_BUILD=0 ;;
        --tzen) TZEN=1 ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

# Find m33mu
if [ -z "$M33MU" ]; then
    # Check common locations
    for path in \
        "$WOLFTPM_DIR/../m33mu/build/m33mu" \
        "$HOME/GitHub/m33mu/build/m33mu" \
        "$(which m33mu 2>/dev/null)"; do
        if [ -x "$path" ]; then
            M33MU="$path"
            break
        fi
    done
fi

if [ -z "$M33MU" ] || [ ! -x "$M33MU" ]; then
    echo "ERROR: m33mu not found. Set M33MU=/path/to/m33mu or install it."
    exit 1
fi

echo "=== fwTPM Emulator Test ==="
echo "  m33mu: $M33MU"
echo "  TZEN: $TZEN"

# Build
if [ $DO_BUILD -eq 1 ]; then
    echo "Building fwTPM STM32 (TZEN=$TZEN, SELFTEST=1)..."
    make -C "$PORT_DIR" clean > /dev/null 2>&1
    if ! make -C "$PORT_DIR" WOLFTPM_DIR="$WOLFTPM_DIR" ${WOLFSSL_DIR:+WOLFSSL_DIR="$WOLFSSL_DIR"} TZEN=$TZEN SELFTEST=1 EXTRA_CFLAGS="-DFWTPM_NO_NV" > /tmp/fwtpm_emu_build.log 2>&1; then
        echo "FAIL: Build failed"
        tail -20 /tmp/fwtpm_emu_build.log
        exit 1
    fi
    echo "  Build OK"
fi

ELF="$PORT_DIR/fwtpm_stm32h5.elf"
if [ ! -f "$ELF" ]; then
    echo "ERROR: $ELF not found"
    exit 1
fi

# Run in emulator
M33MU_ARGS="--cpu stm32h563 --uart-stdout --timeout 30 --quit-on-faults --expect-bkpt 0x4A"
if [ $TZEN -eq 0 ]; then
    M33MU_ARGS="$M33MU_ARGS --no-tz"
fi

echo "Running in m33mu emulator..."
LOG="/tmp/fwtpm_emu_test.log"
set +e
$M33MU $M33MU_ARGS "$ELF" > "$LOG" 2>&1
RC=$?
set -e

# Show UART output (filter emulator noise)
echo ""
echo "--- fwTPM output ---"
grep -E "^===|^fwTPM|^  |^Running|^  Startup|^  SelfTest|^  GetRandom|^  GetCapability|^  Random|^All self|^SELF-TEST" "$LOG" || true
echo "--- end ---"
echo ""

# Check results
if [ $RC -eq 0 ] && grep -q "\\[EXPECT BKPT\\] Success" "$LOG"; then
    echo "PASS: fwTPM self-test (emulator, TZEN=$TZEN)"
    exit 0
else
    echo "FAIL: fwTPM self-test (emulator, TZEN=$TZEN)"
    echo "Full log: $LOG"
    tail -10 "$LOG"
    exit 1
fi
