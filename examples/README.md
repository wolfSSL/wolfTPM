# wolfTPM Examples

These examples demonstrate features of a TPM 2.0 module.

The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_test.h`.

The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See CSR and Certificate Signing below.

## Native API Test

Demonstrates calling native TPM2_* API's.

`./examples/native/native_test`


## Wrapper API Test

Demonstrates calling the wolfTPM2_* wrapper API's.

`./examples/wrap/wrap_test`


## Attestation Use Cases

### TPM signed timestamp, TPM2.0 GetTime

Demonstrates creation of Attestation Identity Keys (AIK) and the generation of TPM signed timestamp that can be later used as protected report of the current system uptime.

This example demonstrates the use of `authSession` (authorization Session) and `policySession` (Policy authorization) to enable the Endorsement Hierarchy necessary for creating AIK. The AIK is used to issue a `TPM2_GetTime` command using the TPM 2.0 native API. This provides a TPM generated and signed timestamp that can be used as a system report of its uptime.

`./examples/timestamp/signed_timestamp`

### TPM signed PCR(system) measurement, TPM2.0 Quote

Demonstrates the generation of TPM2.0 Quote used for attestation of the system state by putting PCR value(s) in a TPM signed structure.

More information about how to test and use PCR attestation can be found in the in [examples/pcr/README.md](./examples/pcr/README.md).

`./examples/pcr/quote`
`./examples/pcr/extend`
`./examples/pcr/reset`


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
`./certs/ca-ecc-cert.der`
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


## TLS Examples

The TLS example uses TPM based ECDHE (ECC Ephemeral key) support. It can be disabled using `CFLAGS="-DWOLFTPM2_USE_SW_ECDHE"` or `#define WOLFTPM2_USE_SW_ECDHE`. We are also looking into using the 2-phase `TPM2_EC_Ephemeral` and `TPM2_ZGen_2Phase` methods for improved performance and scalability.

To force ECC use with wolfSSL when RSA is enabled define `TLS_USE_ECC`.

To use symmetric AES/Hashing/HMAC with the TPM define `WOLFTPM_USE_SYMMETRIC`.

Generation of the Client and Server Certificates requires running:
1. `./examples/csr/csr`
2. `./certs/certreq.sh`
3. Copy the CA files from wolfTPM to wolfSSL certs directory.
    a. `cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem`
    b. `cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem`


### TLS Client

Examples show using a TPM key and certificate for TLS mutual authentication (client authentication).

This example client connects to localhost on on port 11111 by default. These can be overridden using `TLS_HOST` and `TLS_PORT`.

You can validate using the wolfSSL example server this like:
`./examples/server/server -b -p 11111 -g -d`
 
To validate client certificate use the following wolfSSL example server command:
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem`
or
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem`

Then run the wolfTPM TLS client example:
`./examples/tls/tls_client`


### TLS Server

This example shows using a TPM key and certificate for a TLS server.

By default it listens on port 11111 and can be overridden at build-time using the `TLS_PORT` macro.

Run the wolfTPM TLS server example:
`./examples/tls/tls_server`. 

Then run the wolfSSL example client this like:
`./examples/client/client -h localhost -p 11111 -g -d`

To validate server certificate use the following wolfSSL example client comment:
`./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem`
or
`./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem`


Or using your browser: `https://localhost:11111`

With browsers you will get certificate warnings until you load the test CA's `./certs/ca-rsa-cert.pem` and `./certs/ca-ecc-cert.pem` into your OS key store.
For testing most browsers have a way to continue to the site anyways to bypass the warning.


## Clock

Updating the TPM clock

The TPM has internal hardware clock that can be useful to the user. There are two values that the TPM can provide in respect to time.

TPM time is the current uptime, since the last power on sequence. This value can not be changed or modified. There is no mechanism for that. The value is reset at every power sequence.

TPM clock is the total time the TPM has ever been powered. This value can be modified using the TPM2_ClockSet command. The TPM clock can be set only forward.

This way the user can keep track of relative and current time using the TPM clock.

Note: If the new time value makes a change bigger than the TPM clock update interval, then the TPM will first update its volatile register for time and then the non-volatile register for time. This may cause a narrow delay before the commands returns execution to the user. Depending on the TPM manufacturer, the delay can vary from us to few ms.

`./examples/clock/clockSet`

## Benchmark

Performance benchmarks.

`./examples/bench/bench`
