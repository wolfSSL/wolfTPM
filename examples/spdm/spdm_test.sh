#!/bin/bash
# spdm_test.sh - Nuvoton SPDM hardware tests
#
# Copyright (C) 2006-2025 wolfSSL Inc.
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

SPDM_DEMO="${1:-./examples/spdm/spdm_demo}"
CAPS_DEMO="./examples/wrap/caps"
UNIT_TEST="./tests/unit.test"
GPIO_CHIP="gpiochip0"
GPIO_PIN="4"
PASS=0 FAIL=0 TOTAL=0

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

if [ ! -x "$SPDM_DEMO" ]; then
    echo "Error: $SPDM_DEMO not found. Usage: $0 [path-to-spdm_demo]"
    exit 1
fi

echo "=== Nuvoton SPDM Hardware Tests ==="
echo "Demo: $SPDM_DEMO  Caps: $CAPS_DEMO  Unit: $UNIT_TEST"
echo ""

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
    run_test "Cleartext caps (no SPDM)" "$CAPS_DEMO"
else
    echo -e "  ${YELLOW}Skipping: $CAPS_DEMO not found${NC}"
fi

echo ""
echo "=== Results: $TOTAL total, $PASS passed, $FAIL failed ==="
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"; exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"; exit 1
fi
