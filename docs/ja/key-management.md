# 鍵管理

wolfTPM には、TPM 鍵の作成、鍵ブロブとしてのディスクへの保存、外部鍵のインポート、一時的な TPM ハンドルへの再ロードを行うサンプルプログラムが含まれています。このページでは、鍵生成サンプルの流れを説明し、`examples/keygen/` のプログラムと `examples/wrap/` のラッパーユーティリティを一覧にします。

## 鍵生成の概要

`keygen` サンプルは、ストレージ鍵 (SRK) の配下に TPM 鍵を作成し、鍵ブロブをディスクに書き出します。`keyload` サンプルはそのブロブを読み込み、一時的な TPM ハンドルにロードします。

```sh
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

対称鍵と keyed hash 鍵も同じ流れで扱えます。

```sh
$ ./examples/keygen/keygen -sym=aescfb128
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: SYMCIPHER
		 aescfb mode, 128 keybits
	Template: Default
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Symmetric template
Creating new SYMCIPHER key...
Created new key (pub 50, priv 142 bytes)
Wrote 198 bytes to keyblob.bin

$ ./examples/keygen/keyload
TPM2.0 Key load example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 198 bytes from keyblob.bin
Reading the private part of the key
Loaded key to 0x80000001

$ ./examples/keygen/keygen -keyedhash
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: KEYEDHASH
	Template: Default
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Keyed Hash template
Creating new KEYEDHASH key...
TPM2_Create key: pub 48, priv 158
Public Area (size 48):
  Type: KEYEDHASH (0x8), name: SHA256 (0xB), objAttr: 0x40460, authPolicy sz: 0
  Keyed Hash: scheme: HMAC (0x5), scheme hash: SHA256 (0xB), unique size 32
TPM2_Load Key Handle 0x80000001
New key created and loaded (pub 48, priv 158 bytes)
Wrote 212 bytes to keyblob.bin
```

ファイル名を指定しない場合は、デフォルトの `keyblob.bin` が使用されます。このため、`keygen` と `keyload` は追加のパラメータなしで実行でき、手早いデモに適しています。`keygen` が対応するアルゴリズムとオプションの一覧は、いずれかの `--help` スイッチで確認できます。

`keyimport` サンプルは、秘密鍵を TPM 鍵ブロブとしてラップし、ディスクに保存します。その後 `keyload` でロードできます。

```sh
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

`keyload` が受け取る引数は、保存された鍵のファイル名だけです。RSA か ECC かといったスキームは鍵ブロブの中に保存されているため、鍵の種類を指定する必要はありません。

鍵の作成時に認可値を保護するには、`keygen` に `-aes` または `-xor` を追加します。[サンプルの概要](examples-overview.md)を参照してください。

## プログラム (examples/keygen/)

| プログラム | 説明 |
| --- | --- |
| `create_primary.c` | プライマリ鍵を作成して保存します。IAK や IDevID など、エンドースメント階層の鍵も扱います。 |
| `keygen.c` | SRK の配下に新しい RSA、ECC、対称鍵、または keyed hash 鍵を作成し、鍵ブロブをディスクに書き出します。 |
| `keyload.c` | ディスクから鍵ブロブを読み込み、一時的な TPM ハンドルにロードします。 |
| `keyimport.c` | 既存の秘密鍵を TPM 鍵ブロブとしてインポートし、ディスクに書き出します。 |
| `external_import.c` | 外部の秘密鍵(サンプルに組み込み済み)を SRK の配下にインポートします。`-rsa` または `-ecc` で SRK の種類を指定し、`-load` で保存済みの `keyblob.bin` を第 3 階層の鍵にロードします。 |
| `ecdh.c` | TPM 鍵を使った ECDH 鍵共有を行い、共有秘密を生成します。 |

## ラッパーユーティリティ (examples/wrap/)

| プログラム | 説明 |
| --- | --- |
| `wrap_test.c` | `wolfTPM2_*` ラッパー API を実行して動作を確認します。 |
| `caps.c` | TPM のケイパビリティを読み取って表示します。 |
| `getrandom.c` | TPM の RNG から乱数バイトを取得します。 |
| `hash.c` | TPM のハッシュシーケンスでメッセージをハッシュします。 |
| `hmac.c` | 永続的な TPM HMAC 鍵で HMAC を計算します。鍵が見つからない場合は作成します。 |
| `encrypt_decrypt.c` | TPM 鍵による対称鍵の暗号化と復号の往復テストです。 |

## NV への鍵の保存

鍵やシークレットは TPM の NV メモリに保存することもでき、必要に応じて認可値を暗号化できます。[シーリングと NVRAM](sealing-and-nvram.md)を参照してください。

## 関連項目

* [サンプルの概要](examples-overview.md)
* [シーリングと NVRAM](sealing-and-nvram.md)
* [アテステーション](attestation.md)
