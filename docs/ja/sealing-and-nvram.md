# シーリングと NVRAM

TPM 2.0 は、安全な保管庫として機能します。このページでは、キーまたは PCR 値に対するシークレットのシーリング、TPM の不揮発性メモリ (NVRAM) へのキーとデータの保存、およびその両方を使用したセキュアブートのルートオブトラストのサンプルを説明します。すべてのサンプルは他の wolfTPM サンプルと一緒にビルドされ、wolfTPM ソースツリーのルートから実行します。

## シールとアンシールの概要

TPM 2.0 は、標準的な Seal/Unseal の手順でシークレットを保護できます。シールは、TPM 2.0 のキーに対して、または PCR 値のセットに対して作成できます。

!!! note
    キーにシールされるシークレットデータの最大サイズは 128 バイトです。

最もシンプルなサンプルのペアは `seal/seal` と `seal/unseal` です。パラメータなしで実行すると、デモ用の使い方が表示されます。

### TPM 2.0 キーへのデータのシール

`seal` サンプルは、新しく生成した TPM 2.0 キーにデータを安全に保存します。このキーが TPM にロードされた場合にのみ、シークレットデータを読み戻すことができます。

シークレットメッセージのシールとアンシールの出力例:

```sh
$ ./examples/seal/seal keyblob.bin mySecretMessage
TPM2.0 Simple Seal example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Sealing the user secret into a new TPM key
Created new TPM seal key (pub 46, priv 141 bytes)
Wrote 193 bytes to keyblob.bin
Key Public Blob 46
Key Private Blob 141

$ ./examples/keygen/keyload -persistent
TPM2.0 Key load example
	Key Blob: keyblob.bin
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
Reading 193 bytes from keyblob.bin
Reading the private part of the key
Loaded key to 0x80000001
Key was made persistent at 0x81000202

$ ./examples/seal/unseal message.raw
Example how to unseal data using TPM2.0
wolfTPM2_Init: success
Unsealing succeeded
Stored unsealed data to file = message.raw

$ cat message.raw
mySecretMessage
```

アンシールに成功すると、データは新しいファイルに保存されます。ファイル名を指定しない場合、`unseal` ツールはデータを `unseal.bin` に保存します。

### 署名付きポリシーによる PCR へのシール

固定の PCR 値に伴う脆弱性なしにシークレットを PCR にシールするには、外部キーが想定される PCR の状態に署名します。下記の Secure boot root of trust と、次のセクションの `seal_policy_auth` サンプルを参照してください。

## シールのサンプル

`examples/seal/` ディレクトリには、異なる認可ポリシーによる TPM 2.0 のシールとアンシールのサンプルが、最もシンプルなものから最も柔軟なものの順に含まれています。

### seal と unseal (パスワードポリシー)

パスワードベースの認可ポリシーを使用する、最もシンプルなシールとアンシールです。

```sh
./examples/seal/seal keyblob.bin mySecretData
./examples/seal/unseal output.bin keyblob.bin
```

### seal_pcr (PCR のみのポリシー)

特定の PCR 値にバインドされたシークレットをシールします。シークレットは、PCR 値がシール時に計測された値と一致する場合にのみアンシールできます。パスワードや署名キーは必要ありません。

ユースケース: Static Root of Trust、シークレットを特定のブート状態にバインドする。

```sh
# Seal and unseal in one step
./examples/seal/seal_pcr -both -pcr=16 -secretstr="MySecret"

# Separate seal/unseal (for example, seal on first boot, unseal on later boots)
./examples/seal/seal_pcr -seal -pcr=16 -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -pcr=16

# With parameter encryption
./examples/seal/seal_pcr -both -pcr=16 -xor -secretstr="MySecret"
./examples/seal/seal_pcr -both -pcr=16 -aes -secretstr="MySecret"

# Custom sealed blob filename
./examples/seal/seal_pcr -seal -sealblob=myblob.bin -secretstr="MySecret"
./examples/seal/seal_pcr -unseal -sealblob=myblob.bin
```

### seal_policy_auth (PolicyAuthorize と PCR)

TPM 内に存在する署名キーと PCR ポリシーを用いた PolicyAuthorize で、シークレットをシールします。署名キーは新しい PCR 値に対してポリシーを再認可できるため、OS アップデートのような認可された変更があってもシークレットを維持できます。

ユースケース: 認可されたポリシー更新を伴う柔軟なメジャードブート。

!!! note
    `authkey.bin` と `sealblob.bin` は一緒に保管する必要があります。署名キーを再生成すると、シールされたブロブはアンシールできなくなります。

```sh
# ECC signing key (default)
./examples/seal/seal_policy_auth -both -ecc -pcr=16 -secretstr="MySecret"

# RSA signing key
./examples/seal/seal_policy_auth -both -rsa -pcr=16 -secretstr="MySecret"

# Separate seal/unseal
./examples/seal/seal_policy_auth -seal -ecc -pcr=16 -secretstr="MySecret"
./examples/seal/seal_policy_auth -unseal -ecc -pcr=16

# With parameter encryption
./examples/seal/seal_policy_auth -both -ecc -pcr=16 -xor -secretstr="MySecret"
./examples/seal/seal_policy_auth -both -rsa -pcr=16 -aes -secretstr="MySecret"
```

### seal_nv (NV ストレージと PCR ポリシー)

PCR ポリシーで保護された TPM の NV (不揮発性) メモリにシークレットを保存します。ファイルベースのシールされたブロブとは異なり、シークレットは完全に TPM の内部に存在します。このプログラムは `examples/nvram/seal_nv` にあります。

ユースケース: 外部ファイルなしで TPM ハードウェア内に保持する必要があるシークレット。

```sh
# Store, read, delete lifecycle
./examples/nvram/seal_nv -store -pcr=16 -secretstr="MySecret"
./examples/nvram/seal_nv -read -pcr=16
./examples/nvram/seal_nv -delete

# Custom NV index
./examples/nvram/seal_nv -store -pcr=16 -nvindex=0x01800204 -secretstr="MySecret"
./examples/nvram/seal_nv -read -pcr=16 -nvindex=0x01800204
./examples/nvram/seal_nv -delete -nvindex=0x01800204
```

### テスト

`seal_test.sh` は、3 つのシールサンプルグループすべてにわたって 28 件のテストを実行します。

```sh
bash examples/seal/seal_test.sh
```

テストには、正常系 (シールとアンシールのライフサイクル、シークレットの検証)、異常系 (PCR の不一致、auth キーの欠落)、パラメータ暗号化のバリエーション (XOR、AES)、カスタムのファイル名と NV インデックスが含まれます。出力では、色付きの PASS、FAIL、SKIP のマーカーとサマリーが使用されます。詳細な出力は `seal_test.log` に保存されます。

| 変数 | デフォルト | 説明 |
|----------|---------|-------------|
| `WOLFCRYPT_ENABLE` | 1 | wolfCrypt のサポートがコンパイルされている |
| `WOLFCRYPT_DEFAULT` | 0 | デフォルト (縮小版) の wolfCrypt 設定を使用している |
| `WOLFCRYPT_ECC` | 1 | ECC のサポートが利用可能 |
| `WOLFCRYPT_RSA` | 1 | RSA のサポートが利用可能 |

シールのサンプルは、`make check` の間に実行される `examples/run_examples.sh` の一部としてもテストされます。

### ポリシーの比較

| 機能 | seal (パスワード) | seal_pcr | seal_policy_auth | seal_nv |
|---------|----------------|----------|-----------------|---------|
| 認可 | パスワード | PCR 値 | 署名キー + PCR | PCR 値 |
| 複雑さ | 低 | 低 | 高 | 中 |
| PCR 変更後も維持 | 該当なし | 不可 | 可 (auth キーあり) | 不可 |
| ストレージ | ファイル | ファイル | ファイル (ブロブ + キー) | TPM NV |
| パラメータ暗号化 | 可 | 可 | 可 | 可 |

## NVRAM へのキーの保存

これらのサンプルは、TPM をキーの安全な保管庫として使用する方法を示します。プログラムは 2 つあります。1 つは TPM キーを TPM の NVRAM に保存し、もう 1 つは NVRAM からキーを取り出します。どちらも、MITM 攻撃から保護するためにパラメータ暗号化を使用できます。NV の保存場所はパスワード認可で保護されており、コマンドラインで `-aes` を指定すると、そのパスワードは暗号化された形式で渡されます。

サンプルを実行する前に、keygen ツールで `keyblob.bin` が生成されていることを確認してください。キーの種類は RSA、ECC、対称キーのいずれでもかまいません。サンプルは秘密部と公開部を保存します。対称キーの場合、公開部は TPM からのメタデータです。

パラメータ暗号化を有効にして RSA キーを保存し、その後読み取る場合の典型的な出力:

```sh
$ ./examples/nvram/store -aes
Parameter Encryption: Enabled (AES CFB).

TPM2_StartAuthSession: sessionHandle 0x2000000
Reading 840 bytes from keyblob.bin
Storing key at TPM NV index 0x1800202 with password protection

Public part = 616 bytes
NV write of public part succeeded

Private part = 222 bytes
Stored 2-byte size marker before the private part
NV write of private part succeeded


$ ./examples/nvram/read -aes
Parameter Encryption: Enabled (AES CFB).

TPM2_StartAuthSession: sessionHandle 0x2000000
Trying to read 616 bytes of public key part from NV
Successfully read public key part from NV

Trying to read size marker of the private key part from NV
Successfully read size marker from NV

Trying to read 222 bytes of private key part from NV
Successfully read private key part from NV

Extraction of key from NVRAM at index 0x1800202 succeeded
Loading SRK: Storage 0x81000200 (282 bytes)
Trying to load the key extracted from NVRAM
Loaded key to 0x80000001
```

`read` サンプルは、公開部と秘密部の両方が NVRAM に保存されている場合、取り出したキーのロードを試みます。`-aes` スイッチはパラメータ暗号化を有効にします。

これらのサンプルは、`-priv` と `-pub` オプションを使用して、秘密部のみ、または公開部のみといった部分的なキー素材でも動作します。パラメータ暗号化なしで、RSA キーペアの秘密部のみを保存する場合の典型的な出力:

```sh
$ ./examples/nvram/store -priv
Parameter Encryption: Not enabled (try -aes or -xor).

Reading 506 bytes from keyblob.bin
Reading the private part of the key
Storing key at TPM NV index 0x1800202 with password protection

Private part = 222 bytes
Stored 2-byte size marker before the private part
NV write of private part succeeded

$ ./examples/nvram/read -priv
Parameter Encryption: Not enabled (try -aes or -xor).

Trying to read size marker of the private key part from NV
Successfully read size marker from NV

Trying to read 222 bytes of private key part from NV
Successfully read private key part from NV

Extraction of key from NVRAM at index 0x1800202 succeeded
```

`read` でキーの取り出しに成功すると、NV インデックスは破棄されます。`read` を再度使用するには、先に `store` を再実行してください。

### NVRAM プログラム

すべてのプログラムは `examples/nvram/` にあります。

| プログラム | 目的 |
|---------|---------|
| `store.c` | TPM キー (秘密部、公開部、または両方) を NV インデックスに保存します。 |
| `read.c` | NV からキーを読み戻してロードし、NV インデックスを削除することもできます。 |
| `counter.c` | NV カウンターを作成してインクリメントします。 |
| `extend.c` | PolicyOR によるバス保護を示す NV extend のサンプルです。 |
| `policy_nv.c` | データを NV に保存し、TPM2_PolicyNV ベースの認可をテストします。 |
| `seal_nv.c` | PCR ポリシーで保護されたシークレットを NV に保存します (シールのサンプル を参照)。 |

## セキュアブートのルートオブトラスト

`examples/boot/` ディレクトリには、wolfBoot などのセキュアブート向けの、TPM ベースのルートオブトラストの設計が含まれています。

### セキュアブートの ROT

公開鍵ベースのルートオブトラストを TPM に保存するための設計:

1. すべての通信に AES-CFB パラメータ暗号化 (salted および bound) を使用します。
2. デバイス固有のパラメータからパスワードを導出し、NV をロードする (認証する) ための "auth" として使用します。
3. NV には公開鍵のハッシュが格納されます (ハッシュは `.config` の設定と一致します)。
4. wolfBoot は引き続き内部に公開鍵を保持しており、NV が未設定の場合は TPM の NV を書き込みます。
5. NV はロックされ、プラットフォーム階層の下に作成されます。

例:

```sh
$ ./examples/boot/secure_rot -write=../wolfBoot/wolfboot_signing_public_key.der -lock
TPM2: Caps 0x00000000, Did 0x0000, Vid 0x0000, Rid 0x 0
TPM2_Startup pass
TPM2_SelfTest pass
NV Auth (32)
	19 3f bf 0c bb 90 ca a1 40 96 a6 ee 8e fc 7c 3f | .?......@.....|?
	c1 c2 7f 1d c3 e0 a2 5e c7 72 5a a1 94 76 63 53 | .......^.rZ..vcS
Parameter Encryption: Enabled. (AES CFB)

TPM2_StartAuthSession: handle 0x2000000, algorithm AES
TPM2_StartAuthSession: sessionHandle 0x2000000
Storing hash of public key file ../wolfBoot/wolfboot_signing_public_key.der to NV index 0x1400200 with password protection

Public Key Hash (32)
	e3 29 f9 9e 56 93 6e 24 02 34 13 81 0f 7c 73 4d | .)..V.n$.4...|sM
	8f 9d 63 b8 8f 43 39 7b e5 46 93 dd 77 58 77 29 | ..c..C9{.F..wXw)
TPM2_NV_ReadPublic: Sz 14, Idx 0x1400200, nameAlg 11, Attr 0x42072005, authPol 0, dataSz 32, name 34
TPM2_NV_DefineSpace: Auth 0x4000000c, Idx 0x1400200, Attribs 0x1107763205, Size 32
TPM2_NV_Write: Auth 0x1400200, Idx 0x1400200, Offset 0, Size 32
Wrote 32 bytes to NV 0x1400200
Reading NV 0x1400200 public key hash
TPM2_NV_ReadPublic: Sz 14, Idx 0x1400200, nameAlg 11, Attr 0x62072005, authPol 0, dataSz 32, name 34
TPM2_NV_Read: Auth 0x1400200, Idx 0x1400200, Offset 0, Size 32
Read Public Key Hash (32)
	e3 29 f9 9e 56 93 6e 24 02 34 13 81 0f 7c 73 4d | .)..V.n$.4...|sM
	8f 9d 63 b8 8f 43 39 7b e5 46 93 dd 77 58 77 29 | ..c..C9{.F..wXw)
Locking NV index 0x1400200
NV 0x1400200 locked
TPM2_FlushContext: Closed handle 0x2000000
```

### セキュアブートの暗号鍵ストレージ

脆弱性の問題なしにシークレットを PCR にシールするには、外部キーが PCR の状態に署名します。

| ツール | 目的 |
|------|---------|
| `./examples/pcr/policy_sign` | PCR ポリシー用のダイジェストに署名します。署名を出力し、`-outpolicy` を指定すると公開鍵に対する認可ポリシーダイジェストも出力します。 |
| `./examples/boot/secret_seal` | 公開鍵に対する認可ポリシーダイジェストを使用してシークレットをシールします。シークレットを指定しない場合は、ランダムな値が生成されてシールされます。 |
| `./examples/boot/secret_unseal` | 署名付き認可ポリシーと公開鍵を使用してシークレットをアンシールします。 |

署名付き PCR ポリシーを作成します。

```sh
# Extend "aaa" to test PCR 16
echo aaa > aaa.bin
./examples/pcr/reset 16
./examples/pcr/extend 16 aaa.bin

# RSA sign this PCR (result to pcrsig.bin), also creates policyauth.bin from the public key
./examples/pcr/policy_sign -pcr=16 -rsa -key=./certs/example-rsa2048-key.der -out=pcrsig.bin -outpolicy=policyauth.bin
# OR
# ECC sign
./examples/pcr/policy_sign -pcr=16 -ecc -key=./certs/example-ecc256-key.der -out=pcrsig.bin -outpolicy=policyauth.bin
```

公開鍵に基づく、その署名付きポリシーを使用して、シールされたシークレットを作成します。

```sh
# Create a keyed hash sealed object using the policy authorization for the public key
./examples/boot/secret_seal -rsa -policy=policyauth.bin -out=sealblob.bin
./examples/boot/secret_seal -ecc -policy=policyauth.bin -out=sealblob.bin
# OR
# Provide the public key for policy authorization (instead of -policy=)
./examples/boot/secret_seal -rsa -publickey=./certs/example-rsa2048-key-pub.der -out=sealblob.bin
./examples/boot/secret_seal -ecc -publickey=./certs/example-ecc256-key-pub.der -out=sealblob.bin
```

アンシール:

```sh
# Unseal using the public key
./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -rsa -publickey=./certs/example-rsa2048-key-pub.der -seal=sealblob.bin
./examples/boot/secret_unseal -pcr=16 -pcrsig=pcrsig.bin -ecc -publickey=./certs/example-ecc256-key-pub.der -seal=sealblob.bin
```

## 関連項目

- [TLS and certificates](tls-and-certificates.md)
- [Management and GPIO](management-and-gpio.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
