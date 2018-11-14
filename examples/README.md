# wolfTPM Examples

These examples demonstrate features of a TPM 2.0 module.

The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_io.h`.

The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See CSR and Certificate Signing below.

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

This example shows using a TPM key and certificate for a TLS server. By default it listens on port 11111 and can be overridden at build-time using the `TLS_PORT` macro.
 
Generation of the Server Certificate requires running:
1. `./examples/csr/csr`
2. `./certs/certreq.sh`

 You can validate using the wolfSSL example client this like:
  `./examples/client/client -h 192.168.0.100 -p 11111 -d -g`
 
Or using your browser: `https://192.168.0.100:11111`

With browsers you will get a certificate warning because it cannot validate the test server certificate.
For testing most browsers have a way to continue to the site anyways to bypass the warning. 
You can also load the generated test CA's at `./certs/ca-rsa-cert.pem` and `./certs/ca-ecc-cert.pem` into your OS key store.


## Benchmark

Performance benchmarks.

`./examples/bench/bench`
