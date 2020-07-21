#!/bin/sh

echo "wolfTPM Quote & Attestation demo"
echo
echo "Starting from a known PCR state"

./examples/pcr/reset

echo
echo "Extending with precalculated hash value"
echo

./examples/pcr/extend

echo
echo "Generating TPM-signed structure with this PCR digest"
echo

./examples/pcr/quote

echo
echo "TPMS_ATTEST structure is saved to a binary file 'quote.blob'"
echo
