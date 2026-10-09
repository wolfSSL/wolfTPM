# TLS and Certificates

This page covers the wolfTPM examples that build on TPM keys for certificates and secure connections: generating a certificate signing request (CSR), signing test certificates, PKCS #7 signing, and TLS client and server programs that keep the private key inside the TPM.

The PKCS #7 and TLS examples create RSA and ECC keys in NV for testing, using handles defined in `./hal/tpm_io.h`. They require generating CSRs and signing them with a test script, as described below.

## CSR

The `csr` example (`examples/csr/csr.c`) generates a Certificate Signing Request for building a certificate based on a TPM key pair.

```sh
./examples/csr/csr
```

It creates two files:

- `./certs/tpm-rsa-cert.csr`
- `./certs/tpm-ecc-cert.csr`

Options:

| Option | Description |
|--------|-------------|
| `-cert` | Make a self signed certificate instead of a CSR. |
| `-signcb` | Use the `wc_SignCert_cb` callback based signing. |

Example output (the base64 body is shortened here):

```sh
./examples/csr/csr
TPM2 CSR Example
Generated/Signed Cert (DER 860, PEM 1236)
-----BEGIN CERTIFICATE REQUEST-----
MIIDWDCCAkACAQIwgZsxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAP
BgNVBAcMCFBvcnRsYW5kMQ0wCwYDVQQEDARUZXN0MRAwDgYDVQQKDAd3b2xmU1NM
...
l/076ekjTI+7PwzBZIG2F3nOIDUmHwe0lAWdU8h9IoAlM6kS22fh6gZZqQg=
-----END CERTIFICATE REQUEST-----

Generated/Signed Cert (DER 467, PEM 704)
-----BEGIN CERTIFICATE REQUEST-----
MIIBzzCCAXUCAQIwgZsxCzAJBgNVBAYTAlVTMQ8wDQYDVQQIDAZPcmVnb24xETAP
...
6AIgBm+EU6m5SDsk7BYmxTQAhgJFrelwymOa7m16kAXnFuU=
-----END CERTIFICATE REQUEST-----
```

The first request is for the RSA key and the second is for the ECC key.

!!! note
    The CSR example needs wolfSSL built with certificate generation and certificate request support (`--enable-certgen --enable-certreq`) and the crypto callback.

## Certificate signing

An external script generates test certificates from the TPM generated CSRs. Normally the CSR would be provided to a trusted CA for signing.

```sh
./certs/certreq.sh
```

The script creates the following X.509 files (also in .pem format):

- `./certs/ca-ecc-cert.der`
- `./certs/ca-rsa-cert.der`
- `./certs/client-rsa-cert.der`
- `./certs/client-ecc-cert.der`
- `./certs/server-rsa-cert.der`
- `./certs/server-ecc-cert.der`

## PKCS #7

The `pkcs7` example (`examples/pkcs7/pkcs7.c`) signs and verifies data with PKCS #7 using a TPM based key. Run these in order:

1. `./examples/csr/csr`
2. `./certs/certreq.sh`
3. `./examples/pkcs7/pkcs7`

The result is displayed on the console.

| Option | Description |
|--------|-------------|
| `-ecc` / `-rsa` | Use an ECC or RSA key (default is RSA). |
| `-incert=file` | Certificate for the key used. Defaults are `./certs/client-rsa-cert.der` and `./certs/client-ecc-cert.der`. |
| `-out=file` | Write the generated PKCS #7 file containing the signed data and certificate. |

Example output:

```sh
./examples/pkcs7/pkcs7
TPM2 PKCS7 Example
PKCS7 Signed Container 1625
PKCS7 Container Verified (using TPM)
PKCS7 Container Verified (using software)
```

## TLS examples

The TLS examples use TPM based ECDHE (ECC ephemeral key) support. Compile-time toggles:

| Define | Effect |
|--------|--------|
| `WOLFTPM2_USE_SW_ECDHE` | Disables use of the TPM for ECC ephemeral key generation and the shared secret. Set with `CFLAGS="-DWOLFTPM2_USE_SW_ECDHE"` or a `#define`. |
| `WOLFTPM_USE_SYMMETRIC` | Enables symmetric AES, hashing and HMAC support through the TPM for the TLS examples. |
| `TLS_USE_ECC` | Forces ECC use with wolfSSL when RSA is also enabled. |

!!! note
    To run the TLS server and client on the same machine, build wolfTPM with `WOLFTPM_TIS_LOCK` (`--enable-tislock`). It enables concurrent access protection for the TPM device.

The programs are in `examples/tls/`:

| Program | Purpose |
|---------|---------|
| `tls_client.c` | TLS client that uses a TPM key and certificate for mutual authentication. |
| `tls_server.c` | TLS server that uses a TPM key and certificate. |
| `tls_client_notpm.c` | TLS client that does not use the TPM, for comparison and benchmarking. |

### Generate the certificates

Generating the client and server certificates requires running:

1. `./examples/keygen/keygen rsa_test_blob.raw -rsa -t`
2. `./examples/keygen/keygen ecc_test_blob.raw -ecc -t`
3. `./examples/csr/csr`
4. `./certs/certreq.sh`
5. Copy the CA files from wolfTPM to the wolfSSL certs directory:

```sh
cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem
cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem
```

The `wolf-ca-rsa-cert.pem` and `wolf-ca-ecc-cert.pem` files come from the wolfSSL example certificates:

```sh
cp ../wolfssl/certs/ca-cert.pem ./certs/wolf-ca-rsa-cert.pem
cp ../wolfssl/certs/ca-ecc-cert.pem ./certs/wolf-ca-ecc-cert.pem
```

### TLS client

The client shows a TPM key and certificate used for TLS mutual authentication (client authentication). The wolfSSL TLS client loads a public key to indicate that mutual authentication is used, and the crypto callback uses the TPM for the private key signing.

By default the client connects to localhost on port 11111. Override with `TLS_HOST` and `TLS_PORT`.

Start a wolfSSL example server:

```sh
./examples/server/server -b -p 11111 -g -d -i -V
```

To validate the client certificate, use one of these instead:

```sh
./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem -i -V
./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem -i -V
```

Then run the wolfTPM TLS client:

```sh
./examples/tls/tls_client -rsa
./examples/tls/tls_client -ecc
```

Example output:

```sh
./examples/tls/tls_client
TPM2 TLS Client Example
Write (29): GET /index.html HTTP/1.0


Read (193): HTTP/1.1 200 OK
Content-Type: text/html
Connection: close

<html>
<head>
<title>Welcome to wolfSSL!</title>
</head>
<body>
<p>wolfSSL has successfully performed handshake!</p>
</body>
</html>
```

### TLS server

The server shows a TPM key and certificate used for a TLS server. It loads the TPM public key, and the crypto callback uses the TPM for the private key signing. By default it listens on port 11111, which can be changed at build time with the `TLS_PORT` macro.

Run the wolfTPM TLS server:

```sh
./examples/tls/tls_server -rsa
./examples/tls/tls_server -ecc
```

Then connect with the wolfSSL example client:

```sh
./examples/client/client -h localhost -p 11111 -g -d
```

To validate the server certificate:

```sh
./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem
./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem
```

You can also browse to `https://localhost:11111`. Browsers show certificate warnings until the test CAs `./certs/ca-rsa-cert.pem` and `./certs/ca-ecc-cert.pem` are loaded into the OS key store. For testing, most browsers allow continuing past the warning.

Example output:

```sh
./examples/tls/tls_server
TPM2 TLS Server Example
Loading RSA certificate and public key
Read (29): GET /index.html HTTP/1.0


Write (193): HTTP/1.1 200 OK
Content-Type: text/html
Connection: close

<html>
<head>
<title>Welcome to wolfSSL!</title>
</head>
<body>
<p>wolfSSL has successfully performed handshake!</p>
</body>
</html>
```

## See Also

- [Sealing and NVRAM](sealing-and-nvram.md)
- [Management and GPIO](management-and-gpio.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
