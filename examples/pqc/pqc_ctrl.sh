#!/bin/bash
# pqc_ctrl.sh - PQC control-center command tests (SealSQ QVault TPM / fwTPM)
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

# Exercises every pqc_ctrl command against a PQC TPM. Point it at the SealSQ
# QVault TPM part (built with --enable-sealsq --enable-pqc) or the fwTPM (built
# with --enable-fwtpm --enable-swtpm, with fwtpm_server listening).

PQC_CTRL="${1:-./examples/pqc/pqc_ctrl}"
PASS=0 FAIL=0 TOTAL=0

if [ -t 1 ]; then
    GREEN='\033[0;32m' RED='\033[0;31m' NC='\033[0m'
else
    GREEN='' RED='' NC=''
fi

# run_test NAME EXPECT CMD...
#   EXPECT is text that must appear in the output ("" requires only exit 0).
run_test() {
    local name="$1"; local expect="$2"; shift 2
    local out rc
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name"
    out=$("$@" 2>&1); rc=$?
    if [ $rc -eq 0 ] && { [ -z "$expect" ] || echo "$out" | grep -q "$expect"; }; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} (rc=$rc)"; FAIL=$((FAIL + 1))
        echo "$out" | tail -3 | sed 's/^/    /'
    fi
    echo ""
}

# run_neg NAME CMD... — a bad argument set must exit non-zero without running
# any operation. Passes only when the tool rejects it.
run_neg() {
    local name="$1"; shift
    local out rc
    TOTAL=$((TOTAL + 1))
    echo "[$TOTAL] $name (must reject)"
    out=$("$@" 2>&1); rc=$?
    # Must exit non-zero AND print a validation error, so the test proves the
    # argument was rejected — not that the tool failed for some other reason
    # (e.g. no TPM available).
    if [ $rc -ne 0 ] && echo "$out" | grep -q "Error"; then
        echo -e "  ${GREEN}PASS${NC}"; PASS=$((PASS + 1))
    else
        echo -e "  ${RED}FAIL${NC} (rc=$rc, no validation error)"; FAIL=$((FAIL + 1))
    fi
    echo ""
}

if [ ! -x "$PQC_CTRL" ]; then
    echo "Error: $PQC_CTRL not found."
    echo "Build with: ./configure --enable-sealsq --enable-pqc && make"
    echo "Usage: $0 [path-to-pqc_ctrl]"
    exit 1
fi

echo "=== PQC Control Center Tests ==="
echo "Tool: $PQC_CTRL"
echo ""

# Board control / management commands
run_test "Capabilities"           "Vendor"        "$PQC_CTRL" --caps
run_test "Algorithm list"         "ML-KEM"        "$PQC_CTRL" --algs
run_test "Self test"              "SelfTest"      "$PQC_CTRL" --selftest
run_test "Get random (32 bytes)"  "Random 32"     "$PQC_CTRL" --getrandom=32
run_test "PCR read (index 0)"     "PCR0"          "$PQC_CTRL" --pcrread=0
run_test "Flush transient"        "Flushed"       "$PQC_CTRL" --flush

# Pure ML-DSA — every parameter set
for PS in 44 65 87; do
    run_test "ML-DSA-$PS sign/verify" "ML-DSA-$PS" "$PQC_CTRL" --mldsa=$PS
done

# Hash-ML-DSA (SHA-256 pre-hash) — every parameter set
for PS in 44 65 87; do
    run_test "Hash-ML-DSA-$PS sign/verify" "HashML-DSA-$PS" \
        "$PQC_CTRL" --hash-mldsa=$PS
done

# ML-KEM — every parameter set
for PS in 512 768 1024; do
    run_test "ML-KEM-$PS encap/decap" "ML-KEM-$PS" "$PQC_CTRL" --mlkem=$PS
done

# Full matrix in a single process (expect a real op line so a not-compiled-in
# stub, which exits 0 with a "requires --enable-v185" message, cannot pass).
run_test "Full matrix (--all)" "ML-KEM-1024" "$PQC_CTRL" --all

# Irreversible state-modifying commands (a PCR extend cannot be undone without a
# TPM reset; TPM2_Clear wipes the owner hierarchy). Both are off by default so
# the suite never changes TPM state unexpectedly; opt in with PQC_CTRL_CLEAR=1.
if [ "${PQC_CTRL_CLEAR:-0}" = "1" ]; then
    run_test "PCR extend (index 16)" "PCR16 extend" "$PQC_CTRL" --pcrextend=16
    run_test "TPM clear" "Clear" "$PQC_CTRL" --clear
fi

# Argument-validation negatives: each must be rejected before any op runs.
run_neg "Invalid ML-DSA set"      "$PQC_CTRL" --mldsa=abc
run_neg "Out-of-range getrandom"  "$PQC_CTRL" --getrandom=999
run_neg "Bare pcrextend"          "$PQC_CTRL" --pcrextend
run_neg "Unknown option"          "$PQC_CTRL" --bogus --clear

echo ""
echo "=== Results: $TOTAL total, $PASS passed, $FAIL failed ==="
if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"; exit 0
else
    echo -e "${RED}$FAIL TEST(S) FAILED${NC}"; exit 1
fi
