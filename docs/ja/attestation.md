# アテステーション

wolfTPM には、ローカルアテステーションとリモートアテステーション、TPM 署名付きタイムスタンプ、エンドースメント鍵証明書、デバイス ID 鍵のサンプルが含まれています。このページでは、リモートアテステーションのチャレンジの流れ、PCR Quote、署名付きタイムスタンプ、EK 証明書の検証、製造元の ID 鍵について説明します。

## リモートアテステーションの概要

リモートアテステーションとは、クライアントがアテステーションサーバーに証拠を提示し、サーバーがクライアントが既知の状態にあることを確認する仕組みです。これを成立させるには、まずクライアントとサーバーの間で信頼を確立する必要があります。この信頼確立には、標準の TPM 2.0 コマンドである `TPM2_MakeCredential` と `TPM2_ActivateCredential` を使用します。

1. クライアントは、TPM 2.0 のプライマリアテステーション鍵 (PAK) と、Quote に署名するアテステーション鍵 (AK) の公開部分をサーバーに送ります。
2. `MakeCredential` は PAK の公開部分を使ってチャレンジ(シークレット)を暗号化します。通常、チャレンジは AK の公開部分のダイジェストです。PAK と AK の秘密部分をロードできる TPM だけが復号できます。どちらの鍵も `fixedTPM` 属性を持つため、これらをロードできるのは鍵を作成した TPM だけです。
3. サーバーはチャレンジをクライアントに送ります。
4. `ActivateCredential` は、ロード済みの PAK と AK を使ってチャレンジを復号し、シークレットを復元します。その後、クライアントはサーバーに応答できます。

これにより、クライアントが想定どおりの TPM ID とアテステーション鍵を保持していることをサーバーに証明できます。

!!! note
    チャレンジとレスポンスの交換に使うトランスポートは実装依存であるため、開発者が選択します。選択肢の一つは、wolfSSL を使った TLS 1.3 のクライアントサーバー接続です。

この流れで使用するサンプルは次のとおりです。

| プログラム | 役割 |
| --- | --- |
| `./examples/attestation/make_credential` | サーバーがリモートアテステーションのチャレンジを作成するために使用します。 |
| `./examples/attestation/activate_credential` | クライアントがチャレンジを復号して応答するために使用します。 |
| `./examples/attestation/certify` | 指定した名前のオブジェクトが TPM にロードされていることを証明(アテスト)します。 |
| `./examples/keygen/create_primary` | プライマリ鍵 (PK) とアテステーション鍵 (AK) を作成します。 |

これらのサンプルはすべて `-eh` を受け付けます。これを指定すると、エンドースメント鍵と、エンドースメント階層配下のアテステーション鍵を使用します。EK の秘密部分が TPM の外に出ることはなく、EK は TPM チップごとに固有です。そのため、EK 宛てに暗号化したチャレンジは、その TPM だけが開くことができます。欠点はプライバシーです。EK は TPM を識別するため、アテステーション対象のホストの身元が常に判明します。サンプルは、SRK 配下の AK と EK 配下の AK の両方に対応しており、どちらを使うかは開発者が選択します。

## アテステーション用の鍵の作成

`keygen` サンプルを使って、TPM 2.0 のアテステーション鍵と、プライマリアテステーション鍵 (PAK) として機能するプライマリストレージ鍵を作成します。

```sh
$ ./examples/keygen/keygen -rsa
TPM2.0 Key generation example
	Key Blob: keyblob.bin
	Algorithm: RSA
	Template: AIK
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RSA AIK template
Creating new RSA key...
New key created and loaded (pub 280, priv 222 bytes)
Wrote 508 bytes to keyblob.bin
Wrote 288 bytes to srk.pub
Wrote AK Name digest
```

ここで書き出されるファイル(`keyblob.bin`、`srk.pub`、AK の名前ダイジェスト)は、次の 2 つのステップの入力になります。`keygen` の詳細は[鍵管理](key-management.md)を参照してください。

## MakeCredential と ActivateCredential

### Make credential

アテステーションサーバーは `make_credential` を使ってチャレンジを生成します。シークレットは 32 バイトの乱数で、アテステーション方式によっては対称鍵のシードとして利用できます。

```sh
$ ./examples/attestation/make_credential
Using public key from SRK to create the challenge
Demo how to create a credential challenge for remote attestation
Credential will be stored in cred.blob
wolfTPM2_Init: success
Reading 288 bytes from srk.pub
Reading the private part of the key
Public key for encryption loaded
Read AK Name digest success
TPM2_MakeCredential success
Wrote credential blob and secret to cred.blob, 648 bytes
```

PAK と AK の公開部分をクライアントとサーバーの間で転送する処理は、このサンプルには含まれません。

### Activate credential

クライアントは `activate_credential` を使ってチャレンジを復号します。シークレットは平文で得られ、アテステーションサーバーに送信できます。

```sh
$ ./examples/attestation/activate_credential
Using default values
Demo how to create a credential blob for remote attestation
wolfTPM2_Init: success
Credential will be read from cred.blob
Loading SRK: Storage 0x81000200 (282 bytes)
SRK loaded
Reading 508 bytes from keyblob.bin
Reading the private part of the key
AK loaded at 0x80000001
Read credential blob and secret from cred.blob, 648 bytes
TPM2_ActivateCredential success
```

シークレットを含むレスポンス(平文または対称鍵のシードとして)をサーバーに返送する処理も、このサンプルには含まれません。

### Certify

`certify` サンプルは `TPM2_Certify` を使って、別の鍵に対するアテステーション情報に署名します。これにより、特定の名前を持つオブジェクトが TPM にロードされていることを証明できます。一般的な用途は、制限付き IAK に IDevID のアテステーション情報へ署名させることです。

`create_primary` は、RSA または ECC の IDevID 鍵と IAK 鍵を作成できます。これらはエンドースメント階層の配下に作成され、プライマリ鍵のポリシーについては TCG の「TPM 2.0 Keys for Device Identity and Attestation」仕様に従います。IDevID 鍵は、外部向けの制限なし署名に使用します。IAK は内部アテステーションに使用します。ここでは IAK が IDevID を証明します。

```sh
% ./examples/keygen/create_primary -rsa -eh -iak -keep
TPM2.0 Primary Key generation example
        Algorithm: RSA
        Unique: IAK
        Store Handle: 0x00000000
        Use Parameter Encryption: NULL
Creating new RSA primary key...
Create Primary Handle: 0x80000000

% ./examples/keygen/create_primary -rsa -eh -idevid -keep
TPM2.0 Primary Key generation example
        Algorithm: RSA
        Unique: IDEVID
        Store Handle: 0x00000000
        Use Parameter Encryption: NULL
Creating new RSA primary key...
Create Primary Handle: 0x80000001

% ./examples/attestation/certify -rsa -certify=0x80000001 -signer=0x80000000
Certify 0x80000001 with 0x80000000 to generate TPM-signed attestation info
EK Policy Session: Handle 0x3000000
TPM2_Certify complete
Certify Info 172
RSA Signature: 256

% ./examples/management/flush 0x80000001
Preparing to free TPM2.0 Resources
Freeing 80000001 object

% ./examples/management/flush 0x80000000
Preparing to free TPM2.0 Resources
Freeing 80000000 object
```

ECC の場合は、同じ手順で `-rsa` を `-ecc` に置き換えてください。

## Quote と PCR アテステーション

`examples/pcr/` フォルダには、Platform Configuration Register (PCR) を操作するツールと、TPM 2.0 Quote を生成するツールがあります。より詳細なログを出力するには、`./configure --enable-debug` でビルドしてください。

| プログラム | 目的 |
| --- | --- |
| `./examples/pcr/reset` | PCR の内容をクリアします(制約あり、下記参照)。 |
| `./examples/pcr/extend` | extend 操作で PCR の内容を更新します。 |
| `./examples/pcr/quote` | PCR ダイジェストと TPM 署名を含む TPM 2.0 Quote を生成します。 |
| `./examples/pcr/allocate` | TPM が実装し、割り当て済みの PCR バンクを報告し、割り当てを変更します。 |
| `./examples/pcr/demo.sh` | 上記のツールを実演するスクリプトです。 |
| `./examples/pcr/demo-quote-zip.sh` | システムファイルを計測し、その計測結果に対する TPM 署名付きの証明を生成するスクリプトです。 |

### PCR の基本

PCR を変更できるのは extend 操作だけです。電源投入時に、TPM はすべての PCR をデフォルト値(PCR によって全ビット 0 または全ビット 1)にリセットします。同じ PCR 値に到達できるのは、同じダイジェストを同じ順序で extend した場合だけです。A、B、C の順に extend した結果は C、B、A の順とは異なりますが、どちらの順序も再現可能です。

`TPM2_Extend` は SHA-1 または SHA-256 のハッシュ演算を使って、現在の PCR 値と新しいダイジェストを結合します。

すべての PCR は extend できますが、実行時にリセットできるのは一部だけです。

* PCR0 から 15 はブート時にリセットされ、再度クリアできるのは再起動のみです。
* PCR16 はデバッグ用です。上記のすべてのツールがデフォルトでこれを使用し、テストに安全に使えます。
* PCR17 から 22 は Dynamic Root of Trust Measurement (DRTM) 用に予約されています。

リセットのローカリティは TCG PC Client に従います。PCR16 と 23 はローカリティ 0 から 3、PCR20 から 22 はローカリティ 2 から 4、PCR17 から 19 はローカリティ 4 でリセットされます。ローカリティの選択には `-loc=n` を使用します(`wolfTPM2_SetLocality` を参照)。これは内蔵の TIS/SPI ドライバーと fwTPM に適用されます。

### バンクの割り当て

TPM はハッシュアルゴリズムごとに別々の PCR セットを保持しており、これをバンクと呼びます。どのバンクが存在するかはシリコンで固定されていますが、どのバンクを割り当てるかは `TPM2_PCR_Allocate` でプロビジョニングされ、変更できます。Infineon SLB9672 以降を含む多くのパーツでは、一度に 1 つのバンクしか割り当てられないため、SHA-256 から SHA-384 に移行するには SHA-256 の割り当てを解除する必要があります。SHA-1 は非推奨であり、現行のパーツでは割り当てられません。

!!! warning
    指定した選択内容が割り当てを置き換えます。リクエストで指定されなかったバンクは、割り当てが解除されます。このコマンドにはプラットフォーム階層が必要ですが、OS の下ではプラットフォームファームウェアが通常これを無効にしています(指定した認可に関係なく、TPM は `TPM_RC_HIERARCHY` を返します)。プラットフォーム認証が空のパスワードではないセッションを指定して、`wolfTPM2_AllocatePCRBanks_ex` を使用してください。変更は次の TPM リセット時に有効になるため、TPM の電源を入れ直すかシミュレーターを再起動してから、バンクを再度読み取ってください。バンクを変更すると、すべての `PolicyPCR` ダイジェストが無効になり、PCR 値にシーリングされたデータは unseal できなくなります。

### Quote

`TPM2_Quote` は、PCR ダイジェストを TCG 定義の `TPMS_ATTEST` 構造体に格納し、TPM 署名を付与します。署名は TPM だけが使用できるアテステーション ID 鍵 (AIK) で生成されるため、Quote と PCR ダイジェストの出所が保証されます。

### ツールの使い方

```sh
$ ./examples/pcr/reset -?
Incorrect arguments
Expected usage:
./examples/pcr/reset [pcr] [-loc=n]
* pcr is a PCR index between 0-23 (default 16)
* -loc=n switch to TPM locality n (0-4) before reset
    (PCR 17-19 need locality 4; 20-22 need locality 2-4;
     enforced by the fwTPM and by discrete TPMs like the ST33)
Demo usage without parameters, resets PCR16.
```

```sh
$ ./examples/pcr/extend -?
Incorrect arguments
Expected usage:
./examples/pcr/extend [pcr] [filename]
* pcr is a PCR index between 0-23 (default 16)
* filename points to file(data) to measure
	If wolfTPM is built with --disable-wolfcrypt the file
	must contain SHA256 digest ready for extend operation.
	Otherwise, the extend tool computes the hash using wolfcrypt.
Demo usage without parameters, extends PCR16 with known hash.
```

```sh
$ ./examples/pcr/quote -?
Incorrect arguments
Expected usage:
./examples/pcr/quote [pcr] [filename]
* pcr is a PCR index between 0-23 (default 16)
* filename for saving the TPMS_ATTEST structure to a file
Demo usage without parameters, generates quote over PCR16 and
saves the output TPMS_ATTEST structure to "quote.blob" file.
```

```sh
$ ./examples/pcr/allocate -?
Expected usage:
./examples/pcr/allocate [-sha1] [-sha256] [-sha384] [-sha512]
                        [-restore]
* no algorithm flags: report the current allocation and exit
* -shaN: include that bank in the new allocation (repeatable)
* -restore: put the original allocation back before exiting
Demo usage without parameters, reports the PCR banks.

WARNING: the algorithm flags REPLACE the allocation. Banks not
named are deallocated, every PolicyPCR digest changes, and blobs
sealed to PCR values become unsealable. Many TPMs support only
one active bank at a time.

The new allocation takes effect at the next TPM reset, so power
cycle the TPM (or restart the simulator) and re-run to confirm.
```

フラグを指定しない場合、`allocate` は TPM が持つバンクを報告します。一覧は TPM 自身の `TPM_CAP_PCRS` レスポンスから取得されるため、このビルドで名前を持たないバンクはハッシュアルゴリズム ID として表示され、`pcrSelect` は生のビットマップになります。

```sh
$ ./examples/pcr/allocate
PCR banks:
  Bank       Allocated  pcrSelect
  SHA-256    yes        FFFFFF
  SHA-384    yes        FFFFFF
  SHA-1      no         000000
```

SHA-384 のみの割り当てに移行し、リセット後にそれを確認するには、次のようにします。

```sh
$ ./examples/pcr/allocate -sha384
TPM reported: allocationSuccess YES, maxPCR 24, sizeNeeded 1152, sizeAvailable 4608
PCR allocation staged. It takes effect at the next TPM reset
(Startup(CLEAR) after a _TPM_Init) - power cycle the TPM, or
restart the simulator process, then re-run to confirm.

$ ./examples/pcr/allocate
PCR banks:
  Bank       Allocated  pcrSelect
  SHA-256    no         000000
  SHA-384    yes        FFFFFF
  SHA-1      no         000000
```

1 つのバンクしか有効にできない TPM では、2 つを要求すると `TPM_RC_PCR` で拒否されます。コマンドは受け付けるものの空き容量が足りない TPM は `allocationSuccess = NO` を報告し、ラッパーはこれを、`sizeNeeded` が `sizeAvailable` より大きい `BUFFER_E` として返します。どちらのケースも wolfTPM のエラーではありません。

スクリプトでは `-restore` を使うと、実行後にバンクを元の状態に戻せます。これは起動時に読み取った選択内容を、ビットマップも含めて正確に再適用するため、一部だけ選択されていたバンクも一部だけ選択された状態で元に戻ります。

### 典型的なデモ出力

PCR のサンプルはすべて引数なしで実行できます。次は `./examples/pcr/demo.sh` の出力です。

```sh
$ ./examples/pcr/reset
Demo how to reset a PCR (clear the PCR value)
wolfTPM2_Init: success
Trying to reset PCR16...
TPM2_PCR_Reset success
PCR16 digest:
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 | ................
```

PCR16 はすべて 0 に戻るため、以降の PCR ダイジェストを予測できます。これはブート直後の PCR7 に似ていますが、PCR16 なら再起動せずにテストできます。

```sh
$ ./examples/pcr/extend
Demo how to extend data into a PCR (TPM2.0 measurement)
wolfTPM2_Init: success
Hash to be used for measurement:
000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
TPM2_PCR_Extend success
PCR16 digest:
    bb 22 75 c4 9f 28 ad 52 ca e6 d5 5e 34 a9 74 a5 | ."u..(.R...^4.t.
    8c 7a 3b a2 6f 97 6e 8e cb be 7a 53 69 18 dc 73 | .z;.o.n...zSi..s
```

新しい値は、古い PCR の内容(すべて 0)と、指定した SHA-256 ダイジェストから算出されます。`extend` の前に `reset` を実行すれば、常に同じ値になります。独自のデータを使うには、最初に PCR インデックス(16 を推奨)、2 番目にファイルを渡してください。

```sh
$ ./examples/pcr/quote
Demo of generating signed PCR measurement (TPM2.0 Quote)
wolfTPM2_Init: success
TPM2_CreatePrimary: 0x80000000 (314 bytes)
wolfTPM2_CreateEK: Endorsement 0x80000000 (314 bytes)
TPM2_CreatePrimary: 0x80000001 (282 bytes)
wolfTPM2_CreateSRK: Storage 0x80000001 (282 bytes)
TPM2_StartAuthSession: sessionHandle 0x3000000
TPM2_Create key: pub 280, priv 212
TPM2_Load Key Handle 0x80000002
wolfTPM2_CreateAndLoadAIK: AIK 0x80000002 (280 bytes)
TPM2_Quote: success
TPM with signature attests (type 0x8018):
    TPM signed 1 count of PCRs
    PCR digest:
    c7 d4 27 2a 57 97 7f 66 1f bd 79 30 0a 1b bf ff | ..'*W..f..y0....
    2e 43 57 cc 44 14 7a 82 11 aa 76 3f 9f 1b 3a 6c | .CW.D.z...v?..:l
    TPM generated signature:
    28 dc da 76 33 35 a5 85 2a 0c 0b e8 25 d0 f8 8d | (..v35..*...%...
    1f ce c3 3b 71 64 ed 54 e6 4d 82 af f3 83 18 8e | ...;qd.T.M......
    (remaining signature bytes omitted)
```

TPM が Quote に署名する前に、サンプルはエンドースメント鍵 (EK) を作成します。EK は他の鍵のプライマリ鍵として機能します。続いてストレージ鍵 (SRK) を作成し、その配下に、Quote 構造体に署名するアテステーション ID 鍵 (AIK) を作成します。

### システムファイルの計測(ローカルアテステーション)

システム管理者が、ユーザーのシステム上の `zip` ツールが本物で改ざんされていないことを確認したいとします。管理者は PCR16 をリセットし、バイナリのハッシュで extend し、後の比較の基準となる Quote を生成します。これが `./examples/pcr/demo-quote-zip.sh` の処理です。

```sh
$ ./examples/pcr/reset 16
...
Trying to reset PCR16...
TPM2_PCR_Reset success
...
```

`extend` ツールは `/usr/bin/zip` を wolfCrypt (SHA-256) でハッシュし、wolfTPM が PCR16 に対して `TPM2_PCR_Extend` を発行します。

```sh
$ ./examples/pcr/extend 16 /usr/bin/zip
...
TPM2_PCR_Extend success
PCR16 digest:
    2b bd 54 ae 08 5b 59 ef 90 42 d5 ca 5d df b5 b5 | +.T..[Y..B..]...
    74 3a 26 76 d4 39 37 eb b0 53 f5 82 67 6f b4 aa | t:&v.97..S..go..
```

続いて管理者は、PCR16 の計測結果の証明として Quote を作成します。

```sh
$ ./examples/pcr/quote 16 zip.quote
...
TPM2_Quote: success
TPM with signature attests (type 0x8018):
    TPM signed 1 count of PCRs
...
```

Quote はバイナリファイル `zip.quote` に保存されます。`TPMS_ATTEST` 構造体にはクロックと時刻の情報も含まれます。時刻のアテステーションについては次のセクションを参照してください。

### 暗号化した qualifying data を使う Quote

Quote に指定する qualifying data は、パラメータ暗号化で保護できます。[サンプルの概要](examples-overview.md)を参照してください。

## 署名付きタイムスタンプ (GetTime)

`signed_timestamp` サンプルは、アテステーション ID 鍵 (AIK) を作成し、それを使って TPM 署名付きのタイムスタンプを生成します。このタイムスタンプは、現在のシステム稼働時間を保護して報告するために利用できます。

```sh
./examples/timestamp/signed_timestamp
```

このサンプルは、`authSession`(認可セッション)と `policySession`(ポリシー認可)を使ってエンドースメント階層を有効にします。AIK の作成にはこれが必要です。その後、AIK がネイティブ API 経由で `TPM2_GetTime` コマンドを発行し、TPM が生成して署名したタイムスタンプを返します。

`clock_set` サンプルは TPM2 のクロックを進めます。

```sh
./examples/timestamp/clock_set [time]
```

## エンドースメント鍵証明書

TPM の製造元は、TPM 鍵に基づくエンドースメント証明書をプロビジョニングします。TCG EK Credential Profile は、これらを TCG の NV インデックス範囲 (`TPM_20_TCG_NV_SPACE`) に格納する方法を定義しています。`get_ek_certs` サンプルは、そこに格納された EK 証明書を列挙して検証し、署名に使用できるプライマリ EK ハンドルを作成します。`verify_ek_cert` サンプルは、単一の EK 証明書を信頼済み CA のリストに対して検証します。一部のルート CA と中間 CA は `trusted_certs.h` にロードされています。

```sh
./examples/endorsement/get_ek_certs
./examples/endorsement/verify_ek_cert
```

### サンプルの詳細

1. `wolfTPM2_GetHandles` と `TPM_20_TCG_NV_SPACE` で、TCG NV 範囲内のハンドルを取得します。
2. `wolfTPM2_NVReadPublic` で公開 NV 情報を読み取り、証明書のサイズを取得します。
3. `wolfTPM2_NVReadAuth` で NV インデックスから NV データ(証明書の DER/ASN.1)を読み取ります。
4. `wolfTPM2_GetKeyTemplate_EKIndex` または `wolfTPM2_GetKeyTemplate_EK` で、NV インデックスに対応する EK の公開テンプレートを取得します。
5. `wolfTPM2_CreatePrimaryKey` で、公開テンプレートと `TPM_RH_ENDORSEMENT` 階層を使ってプライマリエンドースメント鍵を作成します。
6. `wc_ParseCert` で ASN.1/DER 証明書を解析し、発行者、シリアル番号などのフィールドを取得します。
7. CA 発行者証明書の URI は `extAuthInfoCaIssuer` にあります。
8. 証明書の公開鍵をインポートし、プライマリ EK の公開 unique 領域と比較します。
9. wolfSSL Certificate Manager で EK 証明書を検証します。`wolfSSL_CertManagerLoadCABuffer` で信頼済み証明書をロードし、`wolfSSL_CertManagerVerifyBuffer` で検証します。
10. 必要に応じて、`wc_DerToPem` で PEM に変換してエクスポートします。

### 証明書チェーンの例

Infineon SLB9672。証明書は次の URL からダウンロードできます(xxx は 3 桁の CA 番号に置き換えてください)。

* `https://pki.infineon.com/OptigaRsaMfrCAxxx/OptigaRsaMfrCAxxx.crt`
* `https://pki.infineon.com/OptigaEccMfrCAxxx/OptigaEccMfrCAxxx.crt`

例:

* Infineon OPTIGA(TM) RSA Root CA 2、続いて Infineon OPTIGA(TM) TPM 2.0 RSA CA 059
* Infineon OPTIGA(TM) ECC Root CA 2、続いて Infineon OPTIGA(TM) TPM 2.0 ECC CA 059

STMicro ST33KTPM:

* STSAFE RSA root CA 02 (`http://sw-center.st.com/STSAFE/STSAFERsaRootCA02.crt`)、続いて STSAFE-TPM RSA intermediate CA 10 (`http://sw-center.st.com/STSAFE/stsafetpmrsaint10.crt`)
* STSAFE ECC root CA 02 (`http://sw-center.st.com/STSAFE/STSAFEEccRootCA02.crt`)、続いて STSAFE-TPM ECC intermediate CA 10 (`http://sw-center.st.com/STSAFE/stsafetpmeccint10.crt`)

ST33KTPM での出力例(証明書の 16 進ダンプは省略しています)。

```
$ ./examples/endorsement/verify_ek_cert
Endorsement Certificate Verify
TPM2: Caps 0x30000415, Did 0x0004, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
TPM2_NV_ReadPublic: Sz 14, Idx 0x1c00002, nameAlg 11, Attr 0x62076801, authPol 0, dataSz 1300, name 34
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 0, Size 768
TPM2_NV_Read: Auth 0x1c00002, Idx 0x1c00002, Offset 768, Size 532
EK Data: 1300
        30 82 05 10 30 82 02 f8 a0 03 02 01 02 02 14 58 | 0...0..........X
        ...
wolfTPM2_HashStart: Handle 0x80000002
wolfTPM2_HashUpdate: Handle 0x80000002, DataSz 764
wolfTPM2_HashFinish: Handle 0x80000002, DigestSz 48
Cert Hash: 48
        ...
Issuer Public Exponent 0x10001, Modulus 512
        ...
TPM2_LoadExternal: 0x80000002
EK Certificate Signature: 512
        ...
TPM2_RSA_Encrypt: 512
Decrypted Sig: 512
        ...
Expected Hash: 48
        ...
Sig Hash: 48
        ...
Certificate signature is valid
TPM2_FlushContext: Closed handle 0x80000002
TPM2_FlushContext: Closed handle 0x80000000
```

## デバイス ID

TCG は、デバイス ID とアテステーション用の鍵を設定するための、TPM 製造元向けガイダンス仕様を公開しています。wolfTPM は `WOLFTPM_MFG_IDENTITY` でこれに対応しており、ST33KTPM でテスト済みです。

ST33KTPM のサンプルには、デフォルトのマスターパスワードがプロビジョニングされており、`TEST_SAMPLE` で有効になります。独自のマスターパスワードを使うには、`TPM2_IAK_SAMPLE_MASTER_PASSWORD` を定義してください。マスターパスワードはデバイスのシリアル番号とともにハッシュされ、これらの鍵にアクセスするための認証値が生成されます。

デフォルトの鍵は、SHA2-384 を使う ECDSA SECP384R1 です。これらは `TPM2_IAK_KEY_HANDLE`、`TPM2_IAK_CERT_HANDLE`、`TPM2_IDEVID_KEY_HANDLE`、`TPM2_IDEVID_CERT_HANDLE` で定義された NV インデックスに格納されます。

## 関連項目

* [サンプルの概要](examples-overview.md)
* [鍵管理](key-management.md)
* [シーリングと NVRAM](sealing-and-nvram.md)
* [対応ハードウェア](supported-hardware.md)
