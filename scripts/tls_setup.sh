#!/bin/sh
#
# Generate keyblobs and certs needed for TLS examples
#

./examples/keygen/keygen rsa_test_blob.raw RSA T
./examples/keygen/keygen ecc_test_blob.raw ECC T
./examples/csr/csr
./certs/certreq.sh

cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem
cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem
