# TLS と証明書

このページでは、証明書と安全な接続のために TPM キーを活用する wolfTPM のサンプルを説明します。具体的には、証明書署名要求 (CSR) の生成、テスト用証明書への署名、PKCS #7 署名、および秘密鍵を TPM の内部に保持する TLS クライアントとサーバーのプログラムです。

PKCS #7 と TLS のサンプルは、`./hal/tpm_io.h` で定義されたハンドルを使用して、テスト用の RSA キーと ECC キーを NV に作成します。以下で説明するように、CSR を生成し、テストスクリプトで署名する必要があります。

## CSR

`csr` サンプル (`examples/csr/csr.c`) は、TPM のキーペアに基づく証明書を作成するための証明書署名要求を生成します。

```sh
./examples/csr/csr
```

2 つのファイルが作成されます。

- `./certs/tpm-rsa-cert.csr`
- `./certs/tpm-ecc-cert.csr`

オプション:

| オプション | 説明 |
|--------|-------------|
| `-cert` | CSR ではなく自己署名証明書を作成します。 |
| `-signcb` | `wc_SignCert_cb` コールバックベースの署名を使用します。 |

出力例 (base64 の本体はここでは短縮しています):

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

最初の要求は RSA キー用、2 番目は ECC キー用です。

!!! note
    CSR サンプルには、証明書生成と証明書要求のサポート (`--enable-certgen --enable-certreq`) およびクリプトコールバックを有効にしてビルドした wolfSSL が必要です。

## 証明書への署名

外部スクリプトが、TPM が生成した CSR からテスト用証明書を生成します。通常は、CSR を信頼できる CA に提供して署名してもらいます。

```sh
./certs/certreq.sh
```

このスクリプトは、次の X.509 ファイル (.pem 形式も作成されます) を作成します。

- `./certs/ca-ecc-cert.der`
- `./certs/ca-rsa-cert.der`
- `./certs/client-rsa-cert.der`
- `./certs/client-ecc-cert.der`
- `./certs/server-rsa-cert.der`
- `./certs/server-ecc-cert.der`

## PKCS #7

`pkcs7` サンプル (`examples/pkcs7/pkcs7.c`) は、TPM ベースのキーを使用して PKCS #7 でデータの署名と検証を行います。次の順序で実行してください。

1. `./examples/csr/csr`
2. `./certs/certreq.sh`
3. `./examples/pkcs7/pkcs7`

結果はコンソールに表示されます。

| オプション | 説明 |
|--------|-------------|
| `-ecc` / `-rsa` | ECC キーまたは RSA キーを使用します (デフォルトは RSA)。 |
| `-incert=file` | 使用するキーの証明書。デフォルトは `./certs/client-rsa-cert.der` と `./certs/client-ecc-cert.der` です。 |
| `-out=file` | 署名付きデータと証明書を含む、生成された PKCS #7 ファイルを書き出します。 |

出力例:

```sh
./examples/pkcs7/pkcs7
TPM2 PKCS7 Example
PKCS7 Signed Container 1625
PKCS7 Container Verified (using TPM)
PKCS7 Container Verified (using software)
```

## TLS サンプル

TLS サンプルは、TPM ベースの ECDHE (ECC 一時鍵) をサポートします。コンパイル時のトグルは次のとおりです。

| 定義 | 効果 |
|--------|--------|
| `WOLFTPM2_USE_SW_ECDHE` | ECC 一時鍵の生成と共有シークレットに TPM を使用しないようにします。`CFLAGS="-DWOLFTPM2_USE_SW_ECDHE"` または `#define` で設定します。 |
| `WOLFTPM_USE_SYMMETRIC` | TLS サンプルで、TPM を通じた対称 AES、ハッシュ、HMAC のサポートを有効にします。 |
| `TLS_USE_ECC` | RSA も有効な場合に、wolfSSL で ECC の使用を強制します。 |

!!! note
    TLS サーバーとクライアントを同じマシンで実行するには、`WOLFTPM_TIS_LOCK` (`--enable-tislock`) を指定して wolfTPM をビルドします。これにより、TPM デバイスへの同時アクセス保護が有効になります。

プログラムは `examples/tls/` にあります。

| プログラム | 目的 |
|---------|---------|
| `tls_client.c` | 相互認証に TPM のキーと証明書を使用する TLS クライアント。 |
| `tls_server.c` | TPM のキーと証明書を使用する TLS サーバー。 |
| `tls_client_notpm.c` | 比較とベンチマークのための、TPM を使用しない TLS クライアント。 |

### 証明書の生成

クライアント証明書とサーバー証明書を生成するには、次を実行する必要があります。

1. `./examples/keygen/keygen rsa_test_blob.raw -rsa -t`
2. `./examples/keygen/keygen ecc_test_blob.raw -ecc -t`
3. `./examples/csr/csr`
4. `./certs/certreq.sh`
5. wolfTPM の CA ファイルを wolfSSL の certs ディレクトリにコピーします。

```sh
cp ./certs/ca-ecc-cert.pem ../wolfssl/certs/tpm-ca-ecc-cert.pem
cp ./certs/ca-rsa-cert.pem ../wolfssl/certs/tpm-ca-rsa-cert.pem
```

`wolf-ca-rsa-cert.pem` と `wolf-ca-ecc-cert.pem` のファイルは、wolfSSL のサンプル証明書から取得します。

```sh
cp ../wolfssl/certs/ca-cert.pem ./certs/wolf-ca-rsa-cert.pem
cp ../wolfssl/certs/ca-ecc-cert.pem ./certs/wolf-ca-ecc-cert.pem
```

### TLS クライアント

クライアントは、TLS の相互認証 (クライアント認証) に使用する TPM のキーと証明書を示します。wolfSSL の TLS クライアントは、相互認証が使用されることを示すために公開鍵をロードし、クリプトコールバックが秘密鍵による署名に TPM を使用します。

デフォルトでは、クライアントはポート 11111 の localhost に接続します。`TLS_HOST` と `TLS_PORT` で上書きできます。

wolfSSL のサンプルサーバーを起動します。

```sh
./examples/server/server -b -p 11111 -g -d -i -V
```

クライアント証明書を検証するには、代わりに次のいずれかを使用します。

```sh
./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem -i -V
./examples/server/server -b -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem -i -V
```

その後、wolfTPM の TLS クライアントを実行します。

```sh
./examples/tls/tls_client -rsa
./examples/tls/tls_client -ecc
```

出力例:

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

### TLS サーバー

サーバーは、TLS サーバーに使用する TPM のキーと証明書を示します。TPM の公開鍵をロードし、クリプトコールバックが秘密鍵による署名に TPM を使用します。デフォルトではポート 11111 で待ち受けます。これはビルド時に `TLS_PORT` マクロで変更できます。

wolfTPM の TLS サーバーを実行します。

```sh
./examples/tls/tls_server -rsa
./examples/tls/tls_server -ecc
```

その後、wolfSSL のサンプルクライアントで接続します。

```sh
./examples/client/client -h localhost -p 11111 -g -d
```

サーバー証明書を検証するには、次のようにします。

```sh
./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-rsa-cert.pem
./examples/client/client -h localhost -p 11111 -g -A ./certs/tpm-ca-ecc-cert.pem
```

`https://localhost:11111` をブラウザで開くこともできます。テスト用 CA の `./certs/ca-rsa-cert.pem` と `./certs/ca-ecc-cert.pem` を OS のキーストアにロードするまで、ブラウザは証明書の警告を表示します。テスト目的であれば、ほとんどのブラウザで警告を無視して続行できます。

出力例:

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

## 関連項目

- [Sealing and NVRAM](sealing-and-nvram.md)
- [Management and GPIO](management-and-gpio.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
