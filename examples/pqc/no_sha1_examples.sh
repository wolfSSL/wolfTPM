#!/bin/sh
# Run examples that use PQC or SHA-256 without requiring SHA-1.
# Build for the selected TPM transport first. For fwTPM, start fwtpm_server.

set -eu

./examples/wrap/hash "wolfTPM SHA-256 smoke test" -sha256
./examples/pqc/pqc_ctrl --caps --algs --pcrread=0
./examples/pqc/mldsa_sign -mldsa=65
./examples/pqc/mlkem_encap -mlkem=768
