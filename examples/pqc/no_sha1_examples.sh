#!/bin/sh
# Run examples that use PQC or SHA-256 without requiring SHA-1.
# Build for the selected TPM transport first. For fwTPM, start fwtpm_server.

set -eu
cd "$(dirname "$0")/../.."

check_example() {
    expected=$1
    shift
    if output=$("$@" 2>&1); then
        printf '%s\n' "$output"
    else
        printf '%s\n' "$output" >&2
        return 1
    fi
    case $output in
        *"$expected"*) ;;
        *) printf 'Expected output missing: %s\n' "$expected" >&2; return 1 ;;
    esac
}

check_example 'Digest (32 bytes):' ./examples/wrap/hash "wolfTPM SHA-256 smoke test" -sha256
check_example 'PCR0 (SHA' ./examples/pqc/pqc_ctrl --caps --algs --pcrread=0
check_example 'Round-trip OK: Pure ML-DSA sign + verify sequence' ./examples/pqc/mldsa_sign -mldsa=65
check_example 'Round-trip OK: encapsulated secret matches decapsulated secret' ./examples/pqc/mlkem_encap -mlkem=768
