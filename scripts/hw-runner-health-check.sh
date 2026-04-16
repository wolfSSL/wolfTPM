#!/usr/bin/env bash
# Pre-flight check for the self-hosted hardware SPDM runner.
# Fails fast (before the 10-minute build) if required device nodes aren't
# present or aren't accessible to the current user.
#
# Usage: hw-runner-health-check.sh <expected_spi_cs_number>
set -euo pipefail

CS="${1:?usage: $0 <spi_cs_number>}"
SPIDEV="/dev/spidev0.${CS}"
GPIOCHIP="/dev/gpiochip0"

echo "[health] runner user: $(id)"

if [ ! -c "$SPIDEV" ]; then
    echo "[health] FAIL: $SPIDEV missing. Is SPI enabled in config.txt? Is the TPM wired to CS${CS}?"
    exit 1
fi
if [ ! -r "$SPIDEV" ] || [ ! -w "$SPIDEV" ]; then
    echo "[health] FAIL: $SPIDEV not rw for $(whoami). Add runner user to 'spi' group."
    exit 1
fi
if [ ! -c "$GPIOCHIP" ]; then
    echo "[health] FAIL: $GPIOCHIP missing."
    exit 1
fi
if ! command -v gpioset >/dev/null; then
    echo "[health] FAIL: gpioset not on PATH. Install the 'gpiod' package."
    exit 1
fi

echo "[health] OK: $SPIDEV accessible, $GPIOCHIP present, gpioset on PATH"
