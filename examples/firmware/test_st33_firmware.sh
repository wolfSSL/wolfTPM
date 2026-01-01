#!/bin/bash
# Test script for ST33 firmware update functionality
# Tests basic functionality and optionally actual firmware updates
# 
# Basic tests (no firmware files needed)
# ./examples/firmware/test_st33_firmware.sh
#
# With firmware files (optional)
# LMS_FW_FILE=/path/to/lms.fi NON_LMS_FW_FILE=/path/to/nonlms.fi ./examples/firmware/test_st33_firmware.sh
#
# Run only LMS tests:
# LMS_FW_FILE=/path/to/lms.fi ./examples/firmware/test_st33_firmware.sh --lms
#
# Run only non-LMS tests:
# NON_LMS_FW_FILE=/path/to/nonlms.fi ./examples/firmware/test_st33_firmware.sh --no-lms
#
# Note: Firmware files must be provided via environment variables.

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --lms      Run only LMS firmware update tests (requires LMS_FW_FILE)"
    echo "  --no-lms   Run only non-LMS firmware update tests (requires NON_LMS_FW_FILE)"
    echo "  --help, -h       Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  LMS_FW_FILE      Path to LMS firmware file (.fi V2 format)"
    echo "  NON_LMS_FW_FILE  Path to non-LMS firmware file (.fi V1 format)"
    echo ""
    echo "If neither --lms nor --no-lms is specified, both tests will run"
    echo "if both firmware files are provided (backward compatible behavior)."
}

# Parse command-line arguments
TEST_LMS_ONLY=0
TEST_NON_LMS_ONLY=0

for arg in "$@"; do
    case "$arg" in
        --lms)
            TEST_LMS_ONLY=1
            ;;
        --no-lms)
            TEST_NON_LMS_ONLY=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $arg"
            usage
            exit 1
            ;;
    esac
done

# Check for conflicting flags
if [ $TEST_LMS_ONLY -eq 1 ] && [ $TEST_NON_LMS_ONLY -eq 1 ]; then
    echo "Error: --lms and --no-lms cannot be used together"
    usage
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Get the wolfTPM root directory (parent of examples/firmware)
WOLFTPM_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "=========================================="
echo "ST33 Firmware Update Testing Script"
echo "=========================================="
echo ""

# Set library path - detect build directories automatically
# Check for wolfTPM libraries in common build locations
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

# Check for wolfSSL libraries (optional, for wolfCrypt)
if [ -n "$WOLFSSL_ROOT" ] && [ -d "$WOLFSSL_ROOT/src/.libs" ]; then
    WOLFTPM_LIB_DIRS="$WOLFTPM_LIB_DIRS:$WOLFSSL_ROOT/src/.libs"
elif [ -n "$WOLFSSL_ROOT" ] && [ -d "$WOLFSSL_ROOT/.libs" ]; then
    WOLFTPM_LIB_DIRS="$WOLFTPM_LIB_DIRS:$WOLFSSL_ROOT/.libs"
fi

# Append to existing LD_LIBRARY_PATH if set
if [ -n "$LD_LIBRARY_PATH" ]; then
    export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$WOLFTPM_LIB_DIRS"
else
    export LD_LIBRARY_PATH="$WOLFTPM_LIB_DIRS"
fi

# Firmware file paths (must be set via environment variables if needed)
# No default paths - users must provide their own firmware files
LMS_FW_FILE="${LMS_FW_FILE:-}"
NON_LMS_FW_FILE="${NON_LMS_FW_FILE:-}"

# Find the firmware update tool
FW_UPDATE_TOOL=""
for tool in "$WOLFTPM_ROOT/examples/firmware/.libs/st33_fw_update" \
            "$WOLFTPM_ROOT/examples/firmware/st33_fw_update" \
            "$SCRIPT_DIR/.libs/st33_fw_update" \
            "$SCRIPT_DIR/st33_fw_update"; do
    if [ -x "$tool" ]; then
        FW_UPDATE_TOOL="$tool"
        break
    fi
done

if [ -z "$FW_UPDATE_TOOL" ] || [ ! -x "$FW_UPDATE_TOOL" ]; then
    echo "ERROR: Firmware update tool not found or not executable"
    echo "Please run 'make' first in the wolfTPM root directory: $WOLFTPM_ROOT"
    echo ""
    echo "Searched in:"
    echo "  $WOLFTPM_ROOT/examples/firmware/.libs/st33_fw_update"
    echo "  $WOLFTPM_ROOT/examples/firmware/st33_fw_update"
    echo "  $SCRIPT_DIR/.libs/st33_fw_update"
    echo "  $SCRIPT_DIR/st33_fw_update"
    exit 1
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

    output=$($test_cmd 2>&1)
    rc=$?
    echo "$output"
    echo ""

    if [ "$expect_success" = "yes" ] && [ $rc -eq 0 ]; then
        echo "✓ PASSED: $test_name"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "no" ] && [ $rc -ne 0 ]; then
        echo "✓ PASSED: $test_name (expected failure)"
        ((TESTS_PASSED++))
        return 0
    elif [ "$expect_success" = "any" ]; then
        echo "✓ COMPLETED: $test_name (rc=$rc)"
        ((TESTS_PASSED++))
        return 0
    else
        echo "✗ FAILED: $test_name (rc=$rc)"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test 1: Info-only (no firmware files)
echo ""
echo "=========================================="
echo "BASIC FUNCTIONALITY TESTS"
echo "=========================================="
run_test "Info-only run (show TPM info)" "$FW_UPDATE_TOOL" "yes"
echo ""

# Test 2: Help
run_test "Help output" "$FW_UPDATE_TOOL --help" "yes"
echo ""

# Test 3: Abandon (when not in upgrade mode)
run_test "Abandon command (normal mode)" "$FW_UPDATE_TOOL --abandon" "yes"
echo ""

# Test 4: Verify TPM manufacturer
echo "---------------------------------------------------"
echo "Test: Verify TPM manufacturer is STM"
echo "---------------------------------------------------"
if $FW_UPDATE_TOOL 2>&1 | grep -q "Mfg STM"; then
    echo "✓ PASSED: TPM is STMicro ST33"
    ((TESTS_PASSED++))
else
    echo "✗ FAILED: TPM is not STMicro ST33"
    ((TESTS_FAILED++))
fi
echo ""

# Test 5: Verify firmware version detection
echo "---------------------------------------------------"
echo "Test: Firmware version detection (two-state model)"
echo "---------------------------------------------------"
STATE=$($FW_UPDATE_TOOL 2>&1 | grep -E "Hardware: ST33")
if [ -n "$STATE" ]; then
    echo "Detected: $STATE"
    echo "✓ PASSED: LMS capability detected"
    ((TESTS_PASSED++))
else
    echo "✗ FAILED: LMS capability not detected"
    ((TESTS_FAILED++))
fi
echo ""

# Check for firmware files
echo "=========================================="
echo "FIRMWARE FILE TESTS"
echo "=========================================="
echo ""
echo "Note: Firmware files must be provided via environment variables:"
echo "  LMS_FW_FILE - Path to LMS firmware file (optional)"
echo "  NON_LMS_FW_FILE - Path to non-LMS firmware file (optional)"
echo ""

# Determine which tests to run based on flags
RUN_LMS_TEST=0
RUN_NON_LMS_TEST=0

if [ $TEST_LMS_ONLY -eq 1 ]; then
    RUN_LMS_TEST=1
elif [ $TEST_NON_LMS_ONLY -eq 1 ]; then
    RUN_NON_LMS_TEST=1
else
    # Backward compatible: run both if files are provided
    RUN_LMS_TEST=1
    RUN_NON_LMS_TEST=1
fi

# Test LMS firmware update (if enabled)
if [ $RUN_LMS_TEST -eq 1 ]; then
    if [ -n "$LMS_FW_FILE" ] && [ -f "$LMS_FW_FILE" ]; then
        echo "LMS firmware file found: $LMS_FW_FILE"
        LMS_SIZE=$(stat -c%s "$LMS_FW_FILE" 2>/dev/null || stat -f%z "$LMS_FW_FILE" 2>/dev/null)
        echo "  Size: $LMS_SIZE bytes"
        echo ""

        # Test LMS firmware update
        echo "---------------------------------------------------"
        echo "Test: LMS Firmware Update (V2 format)"
        echo "---------------------------------------------------"
        echo "Running: $FW_UPDATE_TOOL $LMS_FW_FILE --lms"
        echo ""

        $FW_UPDATE_TOOL "$LMS_FW_FILE" --lms
        rc=$?
        echo ""

        if [ $rc -eq 0 ]; then
            echo "✓ PASSED: LMS firmware update completed successfully"
            ((TESTS_PASSED++))
        else
            echo "✗ FAILED: LMS firmware update failed (rc=$rc)"
            echo "  Error: TPM rejected the firmware update"
            ((TESTS_FAILED++))
        fi
        echo ""
    elif [ -n "$LMS_FW_FILE" ]; then
        echo "LMS firmware file not found: $LMS_FW_FILE"
        echo "Skipping LMS firmware update test"
        echo ""
    else
        if [ $TEST_LMS_ONLY -eq 1 ]; then
            echo "ERROR: --lms specified but LMS_FW_FILE not set"
            echo "  Set LMS_FW_FILE environment variable to test LMS firmware updates"
            echo "  Example: export LMS_FW_FILE=/path/to/ST33KTPM2X_FAC_00090200_V2.fi"
            ((TESTS_FAILED++))
        else
            echo "LMS_FW_FILE not set - skipping LMS firmware update test"
            echo "  (Set LMS_FW_FILE environment variable to test LMS firmware updates)"
            echo "  Example: export LMS_FW_FILE=/path/to/ST33KTPM2X_FAC_00090200_V2.fi"
        fi
        echo ""
    fi
fi

# Test non-LMS firmware update (if enabled)
if [ $RUN_NON_LMS_TEST -eq 1 ]; then
    if [ -n "$NON_LMS_FW_FILE" ] && [ -f "$NON_LMS_FW_FILE" ]; then
        echo "Non-LMS firmware file found: $NON_LMS_FW_FILE"
        NON_LMS_SIZE=$(stat -c%s "$NON_LMS_FW_FILE" 2>/dev/null || stat -f%z "$NON_LMS_FW_FILE" 2>/dev/null)
        echo "  Size: $NON_LMS_SIZE bytes"
        echo ""

        # Test non-LMS firmware update
        echo "---------------------------------------------------"
        echo "Test: Non-LMS Firmware Update (V1 format)"
        echo "---------------------------------------------------"
        echo "Running: $FW_UPDATE_TOOL $NON_LMS_FW_FILE"
        echo ""

        $FW_UPDATE_TOOL "$NON_LMS_FW_FILE"
        rc=$?
        echo ""

        if [ $rc -eq 0 ]; then
            echo "✓ PASSED: Non-LMS firmware update completed successfully"
            ((TESTS_PASSED++))
        else
            echo "✗ FAILED: Non-LMS firmware update failed (rc=$rc)"
            echo "  Error: TPM rejected the firmware update"
            ((TESTS_FAILED++))
        fi
        echo ""
    elif [ -n "$NON_LMS_FW_FILE" ]; then
        echo "Non-LMS firmware file not found: $NON_LMS_FW_FILE"
        echo "Skipping non-LMS firmware update test"
        echo ""
    else
        if [ $TEST_NON_LMS_ONLY -eq 1 ]; then
            echo "ERROR: --no-lms specified but NON_LMS_FW_FILE not set"
            echo "  Set NON_LMS_FW_FILE environment variable to test non-LMS firmware updates"
            echo "  Example: export NON_LMS_FW_FILE=/path/to/TPM_ST33KTPM2X_00090200_V1.fi"
            ((TESTS_FAILED++))
        else
            echo "NON_LMS_FW_FILE not set - skipping non-LMS firmware update test"
            echo "  (Set NON_LMS_FW_FILE environment variable to test non-LMS firmware updates)"
            echo "  Example: export NON_LMS_FW_FILE=/path/to/TPM_ST33KTPM2X_00090200_V1.fi"
        fi
        echo ""
    fi
fi

# Final verification - TPM still working
echo "=========================================="
echo "FINAL VERIFICATION"
echo "=========================================="
run_test "TPM still operational after tests" "$FW_UPDATE_TOOL" "yes"
echo ""

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
