#!/bin/sh

echo "wolfTPM Quote & Attestation demo"
echo
echo "Starting from a known PCR state"

./examples/pcr/reset 16

echo
echo "Extending with precalculated hash value"
echo

./examples/pcr/extend 16 /usr/bin/zip

echo
echo "Generating TPM-signed structure with this PCR digest"
echo

./examples/pcr/quote 16 zip.quote

echo
echo "TPMS_ATTEST structure is saved to a binary file 'zip.quote'"
echo
