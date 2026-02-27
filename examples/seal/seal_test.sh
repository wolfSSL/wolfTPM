#!/bin/bash
# wolfTPM seal/unseal standalone test script.
# Exercises seal_pcr, seal_policy_auth, and seal_nv with full lifecycle.
# Usage: bash examples/seal/seal_test.sh  (from wolfTPM root)

PASS=0; FAIL=0; SKIP=0
LOGFILE="seal_test.log"
rm -f "$LOGFILE"; touch "$LOGFILE"
CLEANUP_FILES=""

# Colors (terminal-aware)
if [ -t 1 ]; then
    GRN="\033[32m"; RED="\033[31m"; YLW="\033[33m"; RST="\033[0m"; BLD="\033[1m"
else
    GRN=""; RED=""; YLW=""; RST=""; BLD=""
fi

# Feature gating (same defaults as run_examples.sh)
: "${WOLFCRYPT_ENABLE:=1}" "${WOLFCRYPT_DEFAULT:=0}"
: "${WOLFCRYPT_ECC:=1}" "${WOLFCRYPT_RSA:=1}"

cleanup() {
    for f in $CLEANUP_FILES; do rm -f "$f"; done
    rm -f sealblob.bin authkey.bin custom_seal.bin aaa_pcr16.bin bbb_pcr16.bin
    if [ -x ./examples/nvram/seal_nv ]; then
        ./examples/nvram/seal_nv -delete >> "$LOGFILE" 2>&1
        ./examples/nvram/seal_nv -delete -nvindex=0x01800204 >> "$LOGFILE" 2>&1
    fi
}
trap cleanup EXIT

pass() { echo -e "  ${GRN}PASS${RST} - $1"; PASS=$((PASS + 1)); }
fail() { echo -e "  ${RED}FAIL${RST} - $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "  ${YLW}SKIP${RST} - $1"; SKIP=$((SKIP + 1)); }

# run_test <desc> <expect_pass|expect_fail> [secret_to_verify] -- <command...>
# If secret_to_verify is provided (non-empty before --), greps output for it.
run_test() {
    local desc="$1" expect="$2"; shift 2
    local secret=""
    if [ "$1" != "--" ]; then secret="$1"; shift; fi
    shift # consume --

    local tmpout="seal_test_tmp_$$.out"
    CLEANUP_FILES="$CLEANUP_FILES $tmpout"
    echo "=== $desc ===" >> "$LOGFILE"
    echo "CMD: $*" >> "$LOGFILE"
    "$@" > "$tmpout" 2>&1; local rc=$?
    cat "$tmpout" >> "$LOGFILE"
    echo "EXIT: $rc" >> "$LOGFILE"

    if [ "$expect" = "expect_pass" ]; then
        if [ $rc -ne 0 ]; then
            fail "$desc (exit code: $rc)"; rm -f "$tmpout"; return 1
        fi
        if [ -n "$secret" ] && ! grep -q "$secret" "$tmpout"; then
            fail "$desc (secret not found in output)"; rm -f "$tmpout"; return 1
        fi
        pass "$desc"; rm -f "$tmpout"; return 0
    else
        if [ $rc -ne 0 ]; then pass "$desc"; else fail "$desc (expected failure)"; fi
        rm -f "$tmpout"
    fi
}

setup_pcr() {
    ./examples/pcr/reset 16 >> "$LOGFILE" 2>&1 || return 1
    echo aaa > aaa_pcr16.bin
    ./examples/pcr/extend 16 aaa_pcr16.bin >> "$LOGFILE" 2>&1
}

change_pcr() {
    echo bbb > bbb_pcr16.bin
    ./examples/pcr/extend 16 bbb_pcr16.bin >> "$LOGFILE" 2>&1
}

# Pre-flight
echo -e "${BLD}wolfTPM Seal Test Suite${RST}"
echo ""
if [ ! -x ./examples/pcr/reset ] || [ ! -x ./examples/pcr/extend ]; then
    echo -e "${RED}ERROR: PCR utilities not found. Build examples first.${RST}"; exit 1
fi
HAS_PCR=0; HAS_PA=0; HAS_NV=0
[ -x ./examples/seal/seal_pcr ] && HAS_PCR=1
[ -x ./examples/seal/seal_policy_auth ] && HAS_PA=1
[ -x ./examples/nvram/seal_nv ] && HAS_NV=1

# ============================================================
# Group 1: seal_pcr (PCR-only policy)
# ============================================================
echo -e "${BLD}Group 1: seal_pcr (PCR-only policy)${RST}"
if [ $HAS_PCR -eq 0 ]; then
    skip "seal_pcr not compiled"
else
    # 1.1: seal+unseal, verify secret
    setup_pcr; S="SealPCRSecret123"
    run_test "1.1 seal_pcr -both" expect_pass "$S" -- \
        ./examples/seal/seal_pcr -both -pcr=16 -secretstr="$S"
    rm -f sealblob.bin

    # 1.2: split seal/unseal
    setup_pcr; S="SealPCRSplit456"
    run_test "1.2a seal_pcr -seal" expect_pass -- \
        ./examples/seal/seal_pcr -seal -pcr=16 -secretstr="$S"
    run_test "1.2b seal_pcr -unseal (verify)" expect_pass "$S" -- \
        ./examples/seal/seal_pcr -unseal -pcr=16
    rm -f sealblob.bin

    # 1.3: PCR mismatch (negative)
    setup_pcr
    run_test "1.3a seal_pcr -seal" expect_pass -- \
        ./examples/seal/seal_pcr -seal -pcr=16 -secretstr="WillFail789"
    change_pcr
    run_test "1.3b seal_pcr -unseal after PCR change (expect fail)" expect_fail -- \
        ./examples/seal/seal_pcr -unseal -pcr=16
    rm -f sealblob.bin

    # 1.4: XOR param encryption
    if [ $WOLFCRYPT_ENABLE -eq 1 ]; then
        setup_pcr; S="SealPCRXor101"
        run_test "1.4 seal_pcr -both -xor" expect_pass "$S" -- \
            ./examples/seal/seal_pcr -both -pcr=16 -xor -secretstr="$S"
        rm -f sealblob.bin
    else
        skip "1.4 seal_pcr -xor (wolfCrypt disabled)"
    fi

    # 1.5: AES param encryption
    if [ $WOLFCRYPT_ENABLE -eq 1 ] && [ $WOLFCRYPT_DEFAULT -eq 0 ]; then
        setup_pcr; S="SealPCRAes202"
        run_test "1.5 seal_pcr -both -aes" expect_pass "$S" -- \
            ./examples/seal/seal_pcr -both -pcr=16 -aes -secretstr="$S"
        rm -f sealblob.bin
    else
        skip "1.5 seal_pcr -aes (wolfCrypt default or disabled)"
    fi

    # 1.6: custom sealblob filename
    setup_pcr; S="SealPCRCustom303"
    run_test "1.6a seal_pcr -sealblob=custom_seal.bin" expect_pass -- \
        ./examples/seal/seal_pcr -seal -pcr=16 -sealblob=custom_seal.bin -secretstr="$S"
    run_test "1.6b seal_pcr -unseal custom blob (verify)" expect_pass "$S" -- \
        ./examples/seal/seal_pcr -unseal -pcr=16 -sealblob=custom_seal.bin
    rm -f custom_seal.bin
fi
echo ""

# ============================================================
# Group 2: seal_policy_auth (PolicyAuthorize)
# ============================================================
echo -e "${BLD}Group 2: seal_policy_auth (PolicyAuthorize)${RST}"
if [ $HAS_PA -eq 0 ]; then
    skip "seal_policy_auth not compiled"
elif [ $WOLFCRYPT_ENABLE -ne 1 ] || [ $WOLFCRYPT_DEFAULT -ne 0 ]; then
    skip "seal_policy_auth requires wolfCrypt (non-default)"
else
    # ECC tests
    if [ $WOLFCRYPT_ECC -eq 1 ]; then
        setup_pcr; S="PolicyAuthECC01"
        run_test "2.1 policy_auth -ecc -both" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -both -ecc -pcr=16 -secretstr="$S"
        rm -f sealblob.bin authkey.bin

        setup_pcr; S="PolicyAuthECCSplit"
        run_test "2.3a policy_auth -ecc -seal" expect_pass -- \
            ./examples/seal/seal_policy_auth -seal -ecc -pcr=16 -secretstr="$S"
        run_test "2.3b policy_auth -ecc -unseal (verify)" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -unseal -ecc -pcr=16
        rm -f sealblob.bin authkey.bin

        setup_pcr
        run_test "2.5a policy_auth -ecc -seal" expect_pass -- \
            ./examples/seal/seal_policy_auth -seal -ecc -pcr=16 -secretstr="WillFailECC"
        rm -f authkey.bin
        run_test "2.5b policy_auth -ecc unseal without auth key (expect fail)" expect_fail -- \
            ./examples/seal/seal_policy_auth -unseal -ecc -pcr=16
        rm -f sealblob.bin authkey.bin

        setup_pcr; S="PolicyAuthECCXor"
        run_test "2.6 policy_auth -ecc -both -xor" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -both -ecc -pcr=16 -xor -secretstr="$S"
        rm -f sealblob.bin authkey.bin
    else
        for t in "2.1 -ecc both" "2.3a -ecc seal" "2.3b -ecc unseal" \
                 "2.5 -ecc PCR change" "2.6 -ecc -xor"; do
            skip "policy_auth $t (ECC disabled)"
        done
    fi

    # RSA tests
    if [ $WOLFCRYPT_RSA -eq 1 ]; then
        setup_pcr; S="PolicyAuthRSA01"
        run_test "2.2 policy_auth -rsa -both" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -both -rsa -pcr=16 -secretstr="$S"
        rm -f sealblob.bin authkey.bin

        setup_pcr; S="PolicyAuthRSASplit"
        run_test "2.4a policy_auth -rsa -seal" expect_pass -- \
            ./examples/seal/seal_policy_auth -seal -rsa -pcr=16 -secretstr="$S"
        run_test "2.4b policy_auth -rsa -unseal (verify)" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -unseal -rsa -pcr=16
        rm -f sealblob.bin authkey.bin

        setup_pcr; S="PolicyAuthRSAAes"
        run_test "2.7 policy_auth -rsa -both -aes" expect_pass "$S" -- \
            ./examples/seal/seal_policy_auth -both -rsa -pcr=16 -aes -secretstr="$S"
        rm -f sealblob.bin authkey.bin
    else
        for t in "2.2 -rsa both" "2.4a -rsa seal" "2.4b -rsa unseal" "2.7 -rsa -aes"; do
            skip "policy_auth $t (RSA disabled)"
        done
    fi
fi
echo ""

# ============================================================
# Group 3: seal_nv (NV + PCR policy)
# ============================================================
echo -e "${BLD}Group 3: seal_nv (NV + PCR policy)${RST}"
if [ $HAS_NV -eq 0 ]; then
    skip "seal_nv not compiled"
else
    # 3.1: store/read/delete lifecycle
    setup_pcr; S="NVSealTest001"
    run_test "3.1a seal_nv -store" expect_pass -- \
        ./examples/nvram/seal_nv -store -pcr=16 -secretstr="$S"
    run_test "3.1b seal_nv -read (verify)" expect_pass "$S" -- \
        ./examples/nvram/seal_nv -read -pcr=16
    run_test "3.1c seal_nv -delete" expect_pass -- \
        ./examples/nvram/seal_nv -delete

    # 3.2: PCR mismatch (negative)
    setup_pcr; S="NVSealFail002"
    run_test "3.2a seal_nv -store" expect_pass -- \
        ./examples/nvram/seal_nv -store -pcr=16 -secretstr="$S"
    change_pcr
    run_test "3.2b seal_nv -read after PCR change (expect fail)" expect_fail -- \
        ./examples/nvram/seal_nv -read -pcr=16
    setup_pcr
    run_test "3.2d seal_nv -delete (cleanup)" expect_pass -- \
        ./examples/nvram/seal_nv -delete

    # 3.3: custom NV index
    setup_pcr; S="NVSealCustom003"
    run_test "3.3a seal_nv -store nvindex=0x01800204" expect_pass -- \
        ./examples/nvram/seal_nv -store -pcr=16 -nvindex=0x01800204 -secretstr="$S"
    run_test "3.3b seal_nv -read nvindex=0x01800204 (verify)" expect_pass "$S" -- \
        ./examples/nvram/seal_nv -read -pcr=16 -nvindex=0x01800204
    run_test "3.3c seal_nv -delete nvindex=0x01800204" expect_pass -- \
        ./examples/nvram/seal_nv -delete -nvindex=0x01800204
fi
echo ""

# Summary
TOTAL=$((PASS + FAIL + SKIP))
echo -e "${BLD}Summary:${RST} $TOTAL tests |" \
    "${GRN}$PASS passed${RST} |" \
    "${RED}$FAIL failed${RST} |" \
    "${YLW}$SKIP skipped${RST}"
echo "Detailed log: $LOGFILE"
[ $FAIL -ne 0 ] && exit 1
exit 0
