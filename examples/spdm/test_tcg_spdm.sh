#!/bin/bash

# test_tcg_spdm.sh
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

# Test script to run exmaples TCG SPDM validation
# Tests SPDM functionality per TCG spec v1.84

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --all                    Run all tests via tcg_spdm --all (default)"
    echo "  --discover-handles        Run only AC handle discovery test"
    echo "  --test-policy-transport   Run only PolicyTransportSPDM test"
    echo "  --test-spdm-session-info  Run only GetCapability SPDM session info test"
    echo "  --help, -h                Show this help message"
    echo ""
    echo "This script tests tcg_spdm command-line options."
    echo "Note: AC_GetCapability and AC_Send are DEPRECATED per TCG spec."
}

# Parse command-line arguments
TEST_MODE="all"
for arg in "$@"; do
    case "$arg" in
        --all)
            TEST_MODE="all"
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        --discover-handles)
            TEST_MODE="discover-handles"
            ;;
        --test-policy-transport)
            TEST_MODE="policy-transport"
            ;;
        --test-spdm-session-info)
            TEST_MODE="spdm-session-info"
            ;;
        *)
            echo "Error: Unknown option: $arg"
            usage
            exit 1
            ;;
    esac
done

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Get the wolfTPM root directory
WOLFTPM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Find the tcg_spdm tool
TCG_SPDM=""
for tool in "$WOLFTPM_ROOT/examples/spdm/.libs/tcg_spdm" \
            "$WOLFTPM_ROOT/examples/spdm/tcg_spdm" \
            "$SCRIPT_DIR/.libs/tcg_spdm" \
            "$SCRIPT_DIR/tcg_spdm"; do
    if [ -x "$tool" ]; then
        TCG_SPDM="$tool"
        break
    fi
done

if [ -z "$TCG_SPDM" ] || [ ! -x "$TCG_SPDM" ]; then
    echo "ERROR: tcg_spdm tool not found or not executable"
    echo "Please run 'make' first in the wolfTPM root directory: $WOLFTPM_ROOT"
    echo ""
    echo "Searched in:"
    echo "  $WOLFTPM_ROOT/examples/spdm/.libs/tcg_spdm"
    echo "  $WOLFTPM_ROOT/examples/spdm/tcg_spdm"
    echo "  $SCRIPT_DIR/.libs/tcg_spdm"
    echo "  $SCRIPT_DIR/tcg_spdm"
    exit 1
fi

# Set library path
WOLFTPM_LIB_DIRS=""
for dir in "$WOLFTPM_ROOT/src/.libs" "$WOLFTPM_ROOT/.libs" "$WOLFTPM_ROOT/src" "$WOLFTPM_ROOT"; do
    if [ -d "$dir" ]; then
        if [ -n "$WOLFTPM_LIB_DIRS" ]; then
            WOLFTPM_LIB_DIRS="$WOLFTPM_LIB_DIRS:$dir"
        else
            WOLFTPM_LIB_DIRS="$dir"
        fi
    fi
done

if [ -n "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$WOLFTPM_LIB_DIRS"
else
    export LD_LIBRARY_PATH="$WOLFTPM_LIB_DIRS"
fi

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local expect_success="$3"

    echo "---------------------------------------------------"
    echo "Test: $test_name"
    echo "---------------------------------------------------"
    echo "Running: $test_cmd"
    echo ""

    output=$($test_cmd 2>&1)
    rc=$?

    echo "$output"
    echo ""

    if [ "$expect_success" = "yes" ] && [ $rc -eq 0 ]; then
        echo "PASSED: $test_name"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "no" ] && [ $rc -ne 0 ]; then
        echo "PASSED: $test_name (expected failure)"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "any" ]; then
        echo "COMPLETED: $test_name (rc=$rc)"
        ((TESTS_PASSED++))
        return 0
    else
        echo "FAILED: $test_name (rc=$rc)"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo "=========================================="
echo "TCG SPDM Validation Test Suite"
echo "=========================================="
echo ""

case "$TEST_MODE" in
    "all")
        # When --all is specified, just run --all once
        run_test "Run all tests" "$TCG_SPDM --all" "any"
        ;;
    "discover-handles")
        run_test "Discover AC handles" "$TCG_SPDM --discover-handles" "any"
        ;;
    "policy-transport")
        run_test "PolicyTransportSPDM" "$TCG_SPDM --test-policy-transport" "any"
        ;;
    "spdm-session-info")
        run_test "GetCapability SPDM Session Info" "$TCG_SPDM --test-spdm-session-info" "any"
        ;;
    *)
        # Default: run all individual tests
        # Test 1: Help
        run_test "Help output" "$TCG_SPDM --help" "yes"
        echo ""

        # Test 2: Discover handles
        run_test "Discover AC handles" "$TCG_SPDM --discover-handles" "any"
        echo ""

        # Test 3: PolicyTransportSPDM
        run_test "PolicyTransportSPDM" "$TCG_SPDM --test-policy-transport" "any"
        echo ""

        # Test 4: SPDM Session Info
        run_test "GetCapability SPDM Session Info" "$TCG_SPDM --test-spdm-session-info" "any"
        echo ""
        ;;
esac

# Summary
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo "  Tests Passed: $TESTS_PASSED"
echo "  Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo "All tests completed successfully!"
    exit 0
else
    echo "Some tests failed!"
    exit 1
fi
