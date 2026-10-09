# はじめに

wolfTPM は、ネイティブ API、ラッパー API、およびビルド成功後すぐに使えるサンプルアプリケーション群を備えた、ポータブルな TPM 2.0 ライブラリです。サンプルは TPM 2.0 モジュールの機能を示し、`examples/tpm_test.h` で定義されたハンドルを使用して、テスト用の RSA 鍵と ECC 鍵を NV ストレージに作成します。このページでは、チェックアウト直後の状態から最初のサンプルを動作させるまでの最短手順を説明します。

## 前提条件と wolfSSL のビルド

wolfTPM には、wolfTPM 用オプションを有効にしてビルドした wolfSSL (wolfCrypt) が必要です。最初に wolfSSL をビルドしてインストールします。

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen CFLAGS="-DWC_RSA_NO_PADDING"
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
    Linux の x86_64 と aarch64 では、オプションなしの `./configure` を実行すると、ソフトウェア TPM バックエンド (swTPM と fwTPM) が自動的に有効になります。これにより、TPM ハードウェアを接続しなくても `make check` を実行できます。`--enable-devtpm` や `--enable-autodetect` などのハードウェア向けパスを選択すると、この既定の動作は無効になります。[システムインターフェース](system-interfaces.md)を参照してください。

ハードウェア固有のビルド手順については、[対応ハードウェア](supported-hardware.md)を参照してください。

## 最初のサンプルを実行する

サンプルを実行する前に、TPM に接続できる状態である必要があります。Linux x86_64 および aarch64 の既定のビルドでは、サンプルはソケット経由でソフトウェア TPM と通信します。`make` はその TPM (`fwtpm_server`) をビルドしますが、起動はしません。別のターミナルで、wolfTPM ディレクトリから次のように起動します。

```sh
./src/fwtpm/fwtpm_server --clear
```

`--clear` オプションは、保存されている NV の状態を削除し、新しい状態の TPM で開始します。サーバーは起動したままにしておいてください。

!!! note
    `caps` やその他のサンプルが接続できるようにするには、ソフトウェア TPM を事前に起動しておく必要があります。ハードウェア向けにビルドした場合は、TPM モジュールを接続し、この手順を省略してください。

最も単純なサンプルは、TPM の機能 (capabilities) を読み取り、永続ハンドルを検索します。

```sh
./examples/wrap/caps
TPM2 Get Capabilities
wolfSSL Entering wolfCrypt_Init
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0
Found 2 persistent handles
```

ここに示した出力は一例です。接続した TPM の製造元とファームウェアの情報が表示されるため、モジュールごと、またソフトウェア TPM では異なる内容になります。

他のサンプルでは、さらに多くの機能を試せます。`./examples/native/native_test` は、ネイティブの `TPM2_*` API を直接呼び出します (スタートアップ、セルフテスト、乱数生成、ハッシュ、PCR 操作など)。PKCS #7 と TLS のサンプルでは、CSR を生成し、テストスクリプトで署名する必要があります。詳細はソースツリー内の `examples/README.md` を参照してください。

サンプルでパラメータ暗号化を使用するには、AES-CFB モードでは `-aes`、XOR モードでは `-xor` を指定します。パラメータ暗号化に対応しているのは、一部の TPM コマンドとレスポンスのみです。

!!! note
    TLS サーバーとクライアントを同じマシン上で実行するには、`WOLFTPM_TIS_LOCK` (`--enable-tislock`) を指定してビルドし、並行アクセスからの保護を有効にしてください。

## 関連項目

- [wolfTPM のビルド](building.md)
- [ビルドオプション](build-options.md)
- [対応ハードウェア](supported-hardware.md)
- [システムインターフェース](system-interfaces.md)
