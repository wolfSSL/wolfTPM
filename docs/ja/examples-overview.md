# サンプルの概要

wolfTPM のサンプルは、ネイティブの `TPM2_*` API と `wolfTPM2_*` ラッパー API の両方を使って TPM 2.0 モジュールを利用する方法を示します。サンプルはライブラリと一緒にビルドされ、インストールが成功すればそのまま実行できます。サンプルをお使いのハードウェアプラットフォームに接続するには、`tpm_io.c` の `TPM2_IoCb` 関数と [HAL I/O コールバックガイド](hal-io-callback.md)を参照してください。

サンプルは、テスト用に NV 上へ RSA 鍵と ECC 鍵を作成します。このとき `./examples/tpm_test.h` で定義されたハンドルを使用します(実行フラグとテスト用ハンドルを参照)。PKCS #7 と TLS のサンプルでは、テストスクリプトで生成して署名した CSR が必要です。手順は `examples/README.md` の CSR と証明書署名のセクションを参照してください。

一部のサンプルはベンダー固有です。たとえば ST33 や NPCT75x TPM 向けの追加 GPIO サンプルがあり、これらは該当のハードウェアでのみ動作します。

## ネイティブ API テスト

ネイティブの `TPM2_*` API の呼び出し方を示します。

```sh
./examples/native/native_test
```

## ラッパー API テスト

`wolfTPM2_*` ラッパー API の呼び出し方を示します。

```sh
./examples/wrap/wrap_test
```

## 暗号プリミティブのサンプル

一般的な TPM 暗号操作を扱う、小さく焦点を絞ったサンプルです。

```sh
./examples/wrap/getrandom [bytes]
./examples/wrap/hash [-sha384|-sha512]
./examples/wrap/encrypt_decrypt [-aescfb|-aesctr|-aescbc]
./examples/keygen/ecdh
```

| コマンド | 内容 |
| --- | --- |
| `getrandom [bytes]` | TPM の RNG から乱数バイトを取得します(デフォルトは 32)。 |
| `hash` | TPM のハッシュシーケンスでメッセージをハッシュします。デフォルトは SHA-256 で、`-sha384` または `-sha512` で変更できます。 |
| `encrypt_decrypt` | 対称鍵による暗号化と復号の往復テストです。デフォルトは AES-CFB です。 |
| `ecdh` | ECDH (P-256) 鍵共有を行い、共有秘密を生成します。 |

!!! note
    多くの TPM は、輸出規制のため `TPM2_EncryptDecrypt` を完全に無効にしています。`encrypt_decrypt` サンプルは、このコマンドが利用できない場合は正常にスキップします。

## パラメータ暗号化

サンプルでパラメータ暗号化を有効にするには、AES-CFB モードなら `-aes`、XOR モードなら `-xor` を使用します。パラメータ暗号化に対応しているのは一部の TPM コマンドとレスポンスのみです。`TPM2_` API のエントリでフラグに `CMD_FLAG_ENC2` または `CMD_FLAG_DEC2` が設定されている場合、そのコマンドはパラメータ暗号化または復号を使用します。

暗号化できるのは TPM コマンドの最初のパラメータだけで、その型は `TPM2B_DATA` である必要があります。たとえば TPM 鍵のパスワード認証や、TPM2.0 Quote の qualifying data が該当します。リクエストとレスポンスは、同時にも別々にも暗号化できます。これは `sessionAttributes` で制御します。

* `TPMA_SESSION_decrypt`: コマンドのリクエスト用
* `TPMA_SESSION_encrypt`: コマンドのレスポンス用

どちらか一方だけ、または同じ認可セッションで両方を設定できます。どれを使うかは開発者が決めます。

パラメータ暗号化を使用するサンプルは次のとおりです。

* 暗号化した認可値を使う鍵生成。[鍵管理](key-management.md)を参照してください。
* 暗号化した NV 認可を使う、鍵用のセキュアボールト。[シーリングと NVRAM](sealing-and-nvram.md)を参照してください。
* 暗号化したユーザーデータを使う TPM2.0 Quote。Quote に指定する qualifying data は、署名される Quote 構造体に含まれる任意のデータです。パラメータ暗号化を使うと、ホストはこのデータを暗号化した状態で TPM に送るため、中間者攻撃から保護されます。[アテステーション](attestation.md)を参照してください。

### ポスト量子セッション鍵 (v1.85)

v1.85 の PQC 対応 TPM では、パラメータ暗号化セッションの鍵として、RSA や ECC のストレージ鍵の代わりにポスト量子プライマリ鍵を使用できます。ML-KEM は復号に対応しており、セッションの salt 鍵として使用します。ML-DSA は署名専用で、セッションの bind 鍵として使用します。RSA や ECC のストレージ鍵が必要な場合(たとえば作成する子鍵の親として)は、従来どおりです。

ML-KEM 鍵でセッションを salt するには `-mlkem[=512|768|1024]` を、ML-DSA 鍵にバインドするには `-mldsa[=44|65|87]` を指定します。これらのフラグは `wrap_test`、`pcr/quote`、`nvram/store`、`nvram/counter` で受け付けられます。`keygen` サンプルでは、`-mlkem` と `-mldsa` が子鍵の種類の選択に使われるため、代わりに `-paramkey=mlkem[=...]` と `-paramkey=mldsa[=...]` を使用します。

```sh
./examples/wrap/wrap_test -aes -mlkem=768
./examples/pcr/quote 16 quote.blob -ecc -xor -mldsa=65
./examples/nvram/counter -aes -mldsa=65
./examples/keygen/keygen keyblob.bin -ecc -aes -paramkey=mlkem=768
```

## 実行フラグとテスト用ハンドル

サンプルで使用するハンドルは `./examples/tpm_test.h` で定義されています。

| 定義 | 値 | 用途 |
| --- | --- | --- |
| `TPM2_DEMO_STORAGE_KEY_HANDLE` | `0x81000200` | 永続ストレージ鍵 (RSA) |
| `TPM2_DEMO_STORAGE_EC_KEY_HANDLE` | `0x81000201` | 永続ストレージ鍵 (ECC) |
| `TPM2_DEMO_PERSISTENT_KEY_HANDLE` | `0x81000202` | 汎用の永続鍵 |
| `TPM2_DEMO_HMAC_KEY_HANDLE` | `0x81000210` | 永続 HMAC 鍵 |

RSA と ECC のテスト用の鍵と証明書は、ベースアドレスにインデックスオフセットを加えた値を使用します。

| 定義 | インデックス | ハンドル | 種類 |
| --- | --- | --- | --- |
| `TPM2_DEMO_RSA_KEY_HANDLE` | `0x20` | `0x81000000 + 0x20` | 永続鍵 |
| `TPM2_DEMO_RSA_CERT_HANDLE` | `0x20` | `0x01800000 + 0x20` | NV インデックス |
| `TPM2_DEMO_ECC_KEY_HANDLE` | `0x21` | `0x81000000 + 0x21` | 永続鍵 |
| `TPM2_DEMO_ECC_CERT_HANDLE` | `0x21` | `0x01800000 + 0x21` | NV インデックス |

!!! warning
    TLS のサーバーとクライアントのサンプルを同一マシンで実行するには、`WOLFTPM_TIS_LOCK` を有効にして wolfTPM をビルドしてください(`./configure --enable-tislock`)。これにより名前付きセマフォが追加され、プロセス間での SPI デバイスへの同時アクセスが保護されます。

## 関連項目

* [鍵管理](key-management.md)
* [アテステーション](attestation.md)
* [シーリングと NVRAM](sealing-and-nvram.md)
* [HAL I/O コールバックガイド](hal-io-callback.md)
