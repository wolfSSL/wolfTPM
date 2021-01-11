# wolfTPM Examples

These examples demonstrate features of a TPM 2.0 module.

The examples create RSA and ECC keys in NV for testing using handles defined in `./examples/tpm_test.h`.

The PKCS #7 and TLS examples require generating CSR's and signing them using a test script. See CSR and Certificate Signing below.

To enable parameter encryption use `-aes` for AES-CFB mode or `-xor` for XOR mode. Only some TPM commands / responses support parameter encryption. If the TPM2_ API has .flags `CMD_FLAG_ENC2` or `CMD_FLAG_DEC2` set then the command will use parameter encryption / decryption.

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

## Parameter Encryption

### TPM2.0 Quote with encrypted user data

Example for demonstrating how to use parameter encryption to protect the user data between the Host and the TPM.

In this example the qualifying data that can be supplied by the user for a Quote operation is protected. Qualifying data is arbitrary data incorporated into the signed Quote structure. Using parameter encryption, wolfTPM enables the Host to transfer that user data in encrypted form to the TPM and vice versa. Thus, protecting the data from man-in-the-middle attacks.

Only the first parameter of a TPM command can be encrypted and the parameter must be of type `TPM2B_DATA`. For example, the password auth of a TPM key or the qualifying data of a TPM2.0 Quote.

The encryption of command request and response can be performed together or separate. There can be a communication exchange between the TPM and a client program where only the parameter in the request command is encrypted.

This behavior depends on the `sessionAttributes`:

- `TPMA_SESSION_encrypt` for command request
- `TPMA_SESSION_decrypt` for command response

Either one can be set separately or both can be set in one authorization session. This is up to the user (developer).

`./examples/pcr/quote_paramenc`

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


1. `./examples/keygen/keygen rsa_test_blob.raw -rsa -t`
2. `./examples/keygen/keygen ecc_test_blob.raw -ecc -t`
3. `./examples/csr/csr`
4. `./certs/certreq.sh`
5. Copy the CA files from wolfTPM to wolfSSL certs directory.
    a. `cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem`
    b. `cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem`

Note: The `wolf-ca-rsa-cert.pem` and `wolf-ca-ecc-cert.pem` files come from the wolfSSL example certificates here:

```
cp ../wolfssl/certs/ca-cert.pem ./certs/wolf-ca-rsa-cert.pem
cp ../wolfssl/certs/ca-ecc-cert.pem ./certs/wolf-ca-ecc-cert.pem
```

### TLS Client

Examples show using a TPM key and certificate for TLS mutual authentication (client authentication).

This example client connects to localhost on on port 11111 by default. These can be overridden using `TLS_HOST` and `TLS_PORT`.

You can validate using the wolfSSL example server this like:
`./examples/server/server -b -p 11111 -g -d -i -V`

To validate client certificate use the following wolfSSL example server command:
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem -i -V`
or
`./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem -i -V`

Then run the wolfTPM TLS client example:
`./examples/tls/tls_client -rsa`
or
`./examples/tls/tls_client -ecc`


### TLS Server

This example shows using a TPM key and certificate for a TLS server.

By default it listens on port 11111 and can be overridden at build-time using the `TLS_PORT` macro.

Run the wolfTPM TLS server example:
`./examples/tls/tls_server -rsa`
or
`./examples/tls/tls_server -ecc`

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

Note: This example can take an optional argument, the time value in milliseconds used for incrementing the TPM clock. Default value is 50000ms (50 seconds).

`./examples/timestamp/clock_set`

## Benchmark

Performance benchmarks.

`./examples/bench/bench`

## Key Generation

Examples for generating a TPM key blob and storing to disk, then loading from disk and loading into temporary TPM handle.

```
$ ./examples/keygen/keygen keyblob.bin -rsa
TPM2.0 Key generation example
Loading SRK: Storage 0x81000200 (282 bytes)
Creating new RSA key...
Created new key (pub 280, priv 222 bytes)
Wrote 840 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 840 bytes from keyblob.bin
Loaded key to 0x80000001


$ ./examples/keygen/keygen keyblob.bin -ecc
TPM2.0 Key generation example
Loading SRK: Storage 0x81000200 (282 bytes)
Creating new ECC key...
Created new key (pub 88, priv 126 bytes)
Wrote 744 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 744 bytes from keyblob.bin
Loaded key to 0x80000001
```

Example for importing a private key as TPM key blob and storing to disk, then loading from disk and loading into temporary TPM handle.

```
$ ./examples/keygen/keyimport keyblob.bin -rsa
TPM2.0 Key import example
Loading SRK: Storage 0x81000200 (282 bytes)
Imported key (pub 278, priv 222 bytes)
Wrote 840 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 840 bytes from keyblob.bin
Loaded key to 0x80000001


$ ./examples/keygen/keyimport keyblob.bin -ecc
TPM2.0 Key Import example
Loading SRK: Storage 0x81000200 (282 bytes)
Imported key (pub 86, priv 126 bytes)
Wrote 744 bytes to keyblob.bin

$ ./examples/keygen/keyload keyblob.bin
TPM2.0 Key load example
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 744 bytes from keyblob.bin
Loaded key to 0x80000001
```

The `keyload` tool takes only one argument, the filename of the stored key. Because the information what is key scheme (RSA or ECC) is contained within the key blob.
