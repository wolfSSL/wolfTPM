#!/bin/sh
# Refresh the wolfSSL example CA certificates used by the TLS examples.
#
# wolf-ca-rsa-cert.pem and wolf-ca-ecc-cert.pem are copies of wolfSSL's own
# example CA certificates. The TLS examples load them to verify the wolfSSL
# example peer, so they must match the wolfSSL tree the examples run against.
# They expire when wolfSSL's do, so refresh them from a wolfSSL checkout.
#
# Usage: WOLFSSL_DIR=/path/to/wolfssl ./certs/refresh-wolf-ca.sh
# WOLFSSL_DIR defaults to the wolfSSL checkout beside this repo.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WOLFSSL_DIR="${WOLFSSL_DIR:-$SCRIPT_DIR/../../wolfssl}"

if [ ! -f "$WOLFSSL_DIR/certs/ca-cert.pem" ]; then
    echo "wolfSSL certs not found at $WOLFSSL_DIR/certs" >&2
    echo "Set WOLFSSL_DIR to your wolfSSL checkout." >&2
    exit 1
fi

cp "$WOLFSSL_DIR/certs/ca-cert.pem"     "$SCRIPT_DIR/wolf-ca-rsa-cert.pem"
cp "$WOLFSSL_DIR/certs/ca-ecc-cert.pem" "$SCRIPT_DIR/wolf-ca-ecc-cert.pem"

echo "Refreshed wolf-ca-rsa-cert.pem and wolf-ca-ecc-cert.pem from $WOLFSSL_DIR"
openssl x509 -in "$SCRIPT_DIR/wolf-ca-rsa-cert.pem" -noout -enddate
openssl x509 -in "$SCRIPT_DIR/wolf-ca-ecc-cert.pem" -noout -enddate
