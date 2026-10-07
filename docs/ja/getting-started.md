# はじめに

wolfTPM は、ネイティブ API、ラッパー API、およびビルド後すぐに使えるサンプルアプリケーション群を備えた、移植性の高い TPM 2.0 ライブラリです。サンプルは TPM 2.0 モジュールの機能を示し、`examples/tpm_test.h` で定義されたハンドルを使って、テスト用の RSA 鍵および ECC 鍵を NV ストレージに作成します。このページでは、新規チェックアウトから最初のサンプルを動作させるまでの最短手順を説明します。

## 前提条件と wolfSSL のビルド

wolfTPM には、wolfTPM 用オプションを有効にしてビルドした wolfSSL (wolfCrypt) が必要です。まず wolfSSL をビルドしてインストールします。

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

`autogen.sh` には automake と libtool が必要です: `sudo apt-get install automake libtool`。

別のディレクトリにインストールした wolfSSL を使用する方法については、[wolfTPM のビルド](building.md)を参照してください。

## wolfTPM のビルド

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure
make
```

!!! note
    Linux の x86_64 および aarch64 では、オプションなしの `./configure` を実行すると、ソフトウェア TPM バックエンド (swTPM と fwTPM) が自動的に有効になります。これにより、TPM ハードウェアを接続せずに `make check` を実行できます。`--enable-devtpm` や `--enable-autodetect` などのハードウェア経路を選択すると、この既定動作は無効になります。[システムインターフェース](system-interfaces.md)を参照してください。

ハードウェア固有のビルド手順については、[対応ハードウェア](supported-hardware.md)を参照してください。

## 最初のサンプルを実行する

最も単純なサンプルは、TPM の機能 (capabilities) を読み取り、永続ハンドルを検索します。

```
./examples/wrap/caps
TPM2 Get Capabilities
wolfSSL Entering wolfCrypt_Init
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0
Found 2 persistent handles
```

出力には使用している TPM の製造元とファームウェアの情報が表示されるため、他のモジュールでは異なる内容になります。

他のサンプルはさらに踏み込んだ内容を扱います。`./examples/native/native_test` は、ネイティブの `TPM2_*` API (スタートアップ、セルフテスト、乱数生成、ハッシュ、PCR 操作など) を直接呼び出します。PKCS #7 および TLS のサンプルでは、CSR を生成し、テストスクリプトで署名する必要があります。詳細は、ソースツリーの `examples/README.md` を参照してください。

サンプルでパラメータ暗号化を使用するには、AES-CFB モードの場合は `-aes`、XOR モードの場合は `-xor` を指定します。パラメータ暗号化をサポートしているのは、一部の TPM コマンドとレスポンスのみです。

!!! note
    TLS サーバーとクライアントを同一マシン上で実行するには、`WOLFTPM_TIS_LOCK` (`--enable-tislock`) を指定してビルドし、並行アクセスの保護を有効にします。

## 関連項目

- [wolfTPM のビルド](building.md)
- [ビルドオプション](build-options.md)
- [対応ハードウェア](supported-hardware.md)
- [システムインターフェース](system-interfaces.md)
