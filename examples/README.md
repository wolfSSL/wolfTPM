# wolfTPM Examples

These examples demonstrate features of a TPM 2.0 module.

The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_io.h`.


## Native API Test

Demonstrates calling native TPM2_* API's.

`./examples/native/native_test`


## Wrapper API Test

Demonstrates calling the wolfTPM2_* wrapper API's.

`./examples/wrap/wrap_test`


## CSR

Generates a Certificate Signing Request for building a certificate based on a TPM key pair.

`./examples/csr/csr`

It creates two files:
`./certs/tpm-rsa-cert.csr`
`./certs/tpm-ecc-cert.csr`


## Certificate Signing

External script for generating test certificates based on TPM generated CSR's. Typically the CSR would be provided to a trusted CA for signing.

`./certs/certreq.sh`

The script creates the following X.509 files (also in .pem format):
`./certs/ca-ecc-cert.der`s
`./certs/ca-rsa-cert.der`
`./certs/client-rsa-cert.der`
`./certs/client-ecc-cert.der`
`./certs/server-rsa-cert.der`
`./certs/server-ecc-cert.der`


## PKCS #7

Example signs and verifies data with PKCS #7 using a TPM based key.

* Must first run:
1. `./examples/csr/csr`
2. `./certs/certreq.sh`
3. `./examples/pkcs7/pkcs7`

The result is displayed to stdout on the console.


## TLS Client

Examples show using a TPM key and certificate for TLS mutual authentication (client authentication).

It uses macros defined at compile time for the host/port. See `TLS_HOST` and `TLS_PORT`.

Generation of the Client Certificate requires running:
1. `./examples/csr/csr`
2. `./certs/certreq.sh`


## TLS Server

This example demonstrates server listens on port 11111 by default and can be overridden at build-time using the `TLS_PORT` macro.
 
 You can validate using the wolfSSL example client this like:
 `./examples/client/client -h 192.168.0.100 -p 11111 -d -g`
 
 Or using your browser: `https://192.168.0.100:11111`


## Benchmark

Performance benchmarks.

`./examples/bench/bench`