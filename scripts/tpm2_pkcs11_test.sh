#!/bin/bash
# tpm2_pkcs11_test.sh
# Run tpm2-pkcs11 (tpm2_ptool + OpenSC pkcs11-tool) against a running TPM,
# either directly or through tpm2-abrmd.
#
# Usage:
#   scripts/tpm2_pkcs11_test.sh
#
# Environment:
#   TPM2_PKCS11_TCTI  TCTI for tpm2-pkcs11 and tpm2_ptool
#                     (default: mssim:host=localhost,port=2321;
#                     use tabrmd:bus_type=session behind tpm2-abrmd)
#   PKCS11_MODULE     path to libtpm2_pkcs11.so (default: searched)
#
# Requirements: tpm2-pkcs11 (libtpm2_pkcs11.so, tpm2_ptool), OpenSC
# pkcs11-tool, openssl
#
# Exit: 0 if all tests pass, 77 if a requirement is missing (SKIP), 1 on failure

TPM2_PKCS11_TCTI="${TPM2_PKCS11_TCTI:-mssim:host=localhost,port=2321}"
export TPM2_PKCS11_TCTI
export TPM2TOOLS_TCTI="$TPM2_PKCS11_TCTI"

if [ -z "$PKCS11_MODULE" ]; then
    PKCS11_MODULE=$(find /usr/lib /usr/local/lib -name 'libtpm2_pkcs11.so*' \
        2>/dev/null | head -1)
fi
for tool in tpm2_ptool tpm2_flushcontext pkcs11-tool openssl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "SKIP: $tool not installed"
        exit 77
    fi
done
if [ -z "$PKCS11_MODULE" ] || [ ! -f "$PKCS11_MODULE" ]; then
    echo "SKIP: libtpm2_pkcs11.so not found"
    exit 77
fi

PIN=1234
SOPIN=5678
LABEL=wolftpm
TMP=$(mktemp -d)
export TPM2_PKCS11_STORE="$TMP/store"
mkdir -p "$TPM2_PKCS11_STORE"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

run_test() {
    local name="$1"
    shift
    if "$@" > "$TMP/out.log" 2>&1; then
        echo "  [PASS]  $name"
        PASS=$((PASS+1))
    else
        echo "  [FAIL]  $name"
        sed 's/^/          /' "$TMP/out.log"
        FAIL=$((FAIL+1))
    fi
}

# Without a resource manager, tpm2-tools and tpm2-pkcs11 leave objects and
# sessions loaded when they exit. Flush them so later steps have free slots.
flush_tpm() {
    case "$TPM2_PKCS11_TCTI" in
        tabrmd*) ;;
        *)
            tpm2_flushcontext -t > /dev/null 2>&1
            tpm2_flushcontext -l > /dev/null 2>&1
            ;;
    esac
}

ptool() {
    tpm2_ptool "$@"
    local rc=$?
    flush_tpm
    return $rc
}

p11() {
    pkcs11-tool --module "$PKCS11_MODULE" --token-label "$LABEL" \
        --login --pin "$PIN" "$@"
    local rc=$?
    flush_tpm
    return $rc
}

echo "=== tpm2-pkcs11 tests (TCTI: $TPM2_PKCS11_TCTI) ==="

run_test "ptool init" ptool init
run_test "ptool addtoken" ptool addtoken --pid=1 --label="$LABEL" \
    --userpin="$PIN" --sopin="$SOPIN"
run_test "ptool addkey ecc256" ptool addkey --label="$LABEL" \
    --userpin="$PIN" --algorithm=ecc256 --key-label=ecc --id=01
run_test "ptool addkey rsa2048" ptool addkey --label="$LABEL" \
    --userpin="$PIN" --algorithm=rsa2048 --key-label=rsa --id=02

run_test "list objects" p11 --list-objects

# Keys are selected by CKA_ID (the ASCII bytes of the tpm2_ptool --id);
# a label match can return another key
# Export public keys for software verification
run_test "read ECC public key" p11 --read-object --type pubkey --id 3031 \
    --output-file "$TMP/ecc.der"
run_test "read RSA public key" p11 --read-object --type pubkey --id 3032 \
    --output-file "$TMP/rsa.der"

# ECDSA (CKM_ECDSA_SHA256) sign, verified by OpenSSL
printf 'wolfTPM tpm2-pkcs11 test' > "$TMP/msg.bin"
run_test "ECDSA-SHA256 sign" p11 --sign --mechanism ECDSA-SHA256 --id 3031 \
    --signature-format openssl --input-file "$TMP/msg.bin" \
    --output-file "$TMP/ecc.sig"
run_test "ECDSA-SHA256 verify (OpenSSL)" openssl dgst -sha256 \
    -verify "$TMP/ecc.der" -keyform DER -signature "$TMP/ecc.sig" \
    "$TMP/msg.bin"

# CKM_ECDSA of an all-zero digest, as for an empty message padded to the
# hash length
head -c 32 /dev/zero > "$TMP/zero.bin"
run_test "ECDSA sign of an all-zero digest" p11 --sign --mechanism ECDSA \
    --id 3031 --input-file "$TMP/zero.bin" --output-file "$TMP/zero.sig"

# RSA-PKCS#1 v1.5 sign, verified by OpenSSL
run_test "RSA-SHA256 sign" p11 --sign --mechanism SHA256-RSA-PKCS --id 3032 \
    --input-file "$TMP/msg.bin" --output-file "$TMP/rsa.sig"
run_test "RSA-SHA256 verify (OpenSSL)" openssl dgst -sha256 \
    -verify "$TMP/rsa.der" -keyform DER -signature "$TMP/rsa.sig" \
    "$TMP/msg.bin"

# RSA-OAEP (SHA-256) encrypted by OpenSSL, decrypted by the TPM
printf 'oaep plaintext' > "$TMP/pt.bin"
run_test "RSA-OAEP encrypt (OpenSSL)" openssl pkeyutl -encrypt -pubin \
    -keyform DER -inkey "$TMP/rsa.der" -in "$TMP/pt.bin" -out "$TMP/ct.bin" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256
run_test "RSA-OAEP decrypt" p11 --decrypt --mechanism RSA-PKCS-OAEP \
    --hash-algorithm SHA256 --mgf MGF1-SHA256 --id 3032 \
    --input-file "$TMP/ct.bin" --output-file "$TMP/dec.bin"
run_test "RSA-OAEP plaintext matches" cmp "$TMP/pt.bin" "$TMP/dec.bin"

# RSA-OAEP with SHA-1 and MGF1-SHA-1
run_test "RSA-OAEP-SHA1 encrypt (OpenSSL)" openssl pkeyutl -encrypt -pubin \
    -keyform DER -inkey "$TMP/rsa.der" -in "$TMP/pt.bin" -out "$TMP/ct1.bin" \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha1 \
    -pkeyopt rsa_mgf1_md:sha1
run_test "RSA-OAEP-SHA1 decrypt" p11 --decrypt --mechanism RSA-PKCS-OAEP \
    --hash-algorithm SHA-1 --mgf MGF1-SHA1 --id 3032 \
    --input-file "$TMP/ct1.bin" --output-file "$TMP/dec1.bin"
run_test "RSA-OAEP-SHA1 plaintext matches" cmp "$TMP/pt.bin" "$TMP/dec1.bin"

echo "=== tpm2-pkcs11 results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
