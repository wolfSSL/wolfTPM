# ポスト量子暗号

wolfTPM は、TCG TPM 2.0 Library Specification v1.85 で追加されたポスト量子暗号アルゴリズムを実装しており、wolfCrypt の FIPS 203 (ML-KEM) モジュールおよび FIPS 204 (ML-DSA) モジュールを基盤としています。このページでは、サポートされるアルゴリズム、ビルド方法、および `examples/pqc` に含まれる PQC サンプルについて説明します。

## 概要

サポートされるアルゴリズム:

| アルゴリズム | 規格 | パラメータセット |
|---|---|---|
| ML-DSA (署名) | FIPS 204 | ML-DSA-44 / 65 / 87 |
| HashML-DSA (プリハッシュ署名) | FIPS 204 | 呼び出し側ハッシュ付きの ML-DSA-44 / 65 / 87 |
| ML-KEM (鍵カプセル化) | FIPS 203 | ML-KEM-512 / 768 / 1024 |

wolfTPM は SEALSQ QVault TPM をサポートしています。SEALSQ は、これを v1.85 の PQC アルゴリズムをシリコンに搭載した最初の TPM 2.0 デバイスと位置付けています。SEALSQ は QVault TPM-185 のエンジニアリングサンプルを提供可能としているため、現在の量産および認証の状況については SEALSQ に確認してください。同じ PQC API は、ツリー内の fwTPM サーバーに対しても動作するため、CI やハードウェアが存在しない場合に便利です。QVault TPM シリコンにおける ML-DSA と ML-KEM の実測性能については、このページの末尾にあるベンチマークのセクションを参照してください。

## ビルド

### wolfSSL

wolfSSL は wolfCrypt で ML-DSA と ML-KEM を提供します。

```sh
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen \
            --enable-mldsa --enable-mlkem \
            --enable-harden CFLAGS="-DWC_RSA_NO_PADDING"
make
sudo make install
```

後述の PQC TLS 1.3 デモでは、`--enable-tls-mlkem-standalone` も追加してください。スタンドアロンの `ML_KEM_*` TLS グループにはこのスタンドアロンオプションが必要です。これがない場合、wolfSSL はハイブリッドグループのみを提供し、`wolfSSL_UseKeyShare` はクライアントのデフォルトを拒否します。`gen_pqc_certs` ツールには証明書生成が必要ですが、これは `--enable-wolftpm` がすでに有効にしています。また `--enable-wolftpm` は、TLS サーバーが使用する crypto コールバックと秘密鍵 ID のサポートも提供します。`--enable-pkcallbacks` は別の wolfSSL オプションであるため、そのまま指定してください。このデモには wolfSSL 5.9.4-stable 以降が必要です。

### fwTPM (ソフトウェア TPM)

```sh
./configure --enable-fwtpm --enable-pqc
make
```

fwTPM サーバーは v1.85 のコマンドセット全体を使用するため、configure は `--enable-pqc` を `--enable-v185` に引き上げます。両方のフラグを省略しても、wolfCrypt に ML-DSA と ML-KEM が含まれている場合、configure は v1.85 を自動的に有効にします。明示的に無効にするには `--disable-pqc` を指定してください。

### ハードウェア TPM: SEALSQ QVault

SEALSQ QVault は、現在 v1.85 PQC でサポートされているハードウェア TPM です。

```sh
./configure --enable-sealsq --enable-pqc
make
```

Linux では、カーネルの TPM ドライバーを使用するために `--enable-devtpm` を追加します。プロセス間でトランジェントハンドルを受け渡すサンプルでは、`CFLAGS='-DTPM2_LINUX_DEV="/dev/tpm0"'` も追加してください。デフォルトの `/dev/tpmrm0` は、プロセスがデバイスを閉じるとそれらのハンドルを仮想化して破棄します。シングルクォートで囲んだ `CFLAGS` の値の内側にある二重引用符は、そのまま記述してください。

`--enable-pqc` は、ハードウェア向けに軽量な ML-DSA と ML-KEM のサブセット (`WOLFTPM_PQC`) をビルドします。v1.85 のコマンドセット全体を使用するには `--enable-v185` (`WOLFTPM_V185`) を使用してください。

SHA-1 を使用しない TPM サンプルの例:

```sh
./examples/pqc/pqc_ctrl --caps --algs
./examples/pqc/pqc_ctrl --mldsa=65 --mlkem=768
./examples/wrap/hash "wolfTPM" -sha256
```

### PQC フットプリントの削減

呼び出す操作だけをコンパイルする (バイナリが小さくなり、バッファの最大サイズも小さくなる) には、wolfSSL のフラグに合わせて指定します。

```sh
# ML-DSA verify-only + ML-KEM encapsulate-only (no sign, no decapsulate)
./configure --enable-pqc --enable-mldsa=verify-only --enable-mlkem=enc
```

| フラグ | 値 | 除外されるもの |
|------|--------|-------|
| `--enable-mldsa` | `all` (デフォルト) / `sign-only` / `verify-only` / `no` | 選択されていない ML-DSA 操作 |
| `--enable-mlkem` | `all` (デフォルト) / `enc` / `dec` / `no` | 選択されていない ML-KEM 操作 |
| `--disable-hash-mldsa` | なし | プリハッシュ ML-DSA 鍵のサポート |

これらは `WOLFTPM_NO_MLDSA_SIGN`、`WOLFTPM_NO_MLKEM_DECAP` などの define に対応しており、組み込み開発者は autotools を使わずに `CFLAGS` で直接渡すこともできます。既存の `--enable-v185` ビルドには影響しません (すべての操作がデフォルトで有効です)。両方のアルゴリズムを無効にする (`--enable-mldsa=no --enable-mlkem=no`) と configure エラーになります。ポスト量子暗号のサポートを一切含めずにビルドするには `--disable-pqc` を使用してください。

同じフラグは fwTPM サーバーの削減にも使えます。`--enable-fwtpm --enable-mldsa=verify-only` は、ML-DSA の署名コマンドのハンドラー、ディスパッチエントリー、暗号処理をコンパイルから除外します。ML-KEM は別に制御され、デフォルトの `all` のままです。したがって、PQC の対象が ML-DSA の verify のみであるサーバーをビルドするには、`--enable-mlkem=no` も指定してください。fwTPM は常に v1.85 仕様の全体をビルドするため、これらの削減は `WOLFTPM_V185` の上に適用されます。

!!! note
    削減を行っても、サンプルがアロケーションフリーになるわけではありません。サンプルは引き続き `XMALLOC` で署名バッファと暗号文バッファを確保します。fwTPM には別に `WOLFTPM2_NO_HEAP` オプションがあり、すべてのバッファをスタックに移しますが、その代わりスタック使用量が大幅に増えます。詳細は [fwTPM のビルド](fwtpm/building.md) を参照してください。

## サンプルの実行

```sh
make check
```

上記の fwTPM ビルドでは、`make check` は PQC のカバレッジを含むソフトウェア TPM のテストスイートを実行します。

- `tests/fwtpm_unit.test`: 30 件以上のインプロセス PQC ハンドラーテスト
- `tests/fwtpm_check.sh`: サーバーを起動したうえで、`tests/unit.test` (mssim ソケット経由の PQC ラッパーテスト。ML-DSA Sign/Verify Sequence、ML-KEM Encap/Decap、EncryptSecret ML-KEM など)、`examples/run_examples.sh`、および tpm2-tools スイートを実行します
- `tests/fwtpm_da_retry.sh`: ディクショナリアタックのリトライ確認 (`-DFWTPM_DA_USED_RETRY` を指定したビルドが必要)

`make check` は `tests/pqc_mssim_e2e.sh` を実行しません。PQC に絞った高速なエンドツーエンドの確認には、このスクリプトを直接実行してください。

```sh
./tests/pqc_mssim_e2e.sh
```

fwTPM ビルドでは、以下の個別サンプルを実行する前に、`127.0.0.1:2321` で `fwtpm_server` を起動してください。SEALSQ ビルドでは、設定済みのハードウェアトランスポートを使用します。

```sh
./src/fwtpm/fwtpm_server --clear &
```

fwTPM サーバーの PQC 内部 (8 つの v1.85 コマンド、プライマリ鍵の導出、バッファ定数、仕様解釈上の判断) については、[docs/FWTPM.md](fwtpm/overview.md) を参照してください。

## サンプル

### pqc_ctrl

`pqc_ctrl` は、PQC TPM (SEALSQ QVault TPM または fwTPM) を操作して検証するための単一の CLI です。各コマンドは TPM に対して操作を実行します。すべての鍵操作は最初にトランジェントオブジェクトテーブルをフラッシュするため、オブジェクトメモリが小さい TPM (SEALSQ QVault TPM など) でも、コマンドを連続して実行した際に `TPM_RC_OBJECT_MEMORY` が発生しません。

```sh
./examples/pqc/pqc_ctrl                 # --all (default)
./examples/pqc/pqc_ctrl --caps --algs   # identify + list supported algorithms
./examples/pqc/pqc_ctrl --mldsa=87      # ML-DSA-87 sign/verify
./examples/pqc/pqc_ctrl --mlkem=1024    # ML-KEM-1024 encap/decap
./examples/pqc/pqc_ctrl --selftest --getrandom=32 --pcrread=0
```

| コマンド | 説明 |
|---|---|
| `--caps` | 製造元、ベンダー文字列、ファームウェア、FIPS モード |
| `--algs` | TPM がサポート対象として報告するアルゴリズムの一覧 |
| `--selftest` | `TPM2_SelfTest` |
| `--getrandom[=N]` | N バイトの乱数 (デフォルトは 16) |
| `--pcrread[=idx]` | PCR の読み取り (SHA-256 バンク、なければ SHA-384 にフォールバック) |
| `--pcrextend=idx` | テスト用ダイジェストで PCR を拡張 (インデックスの明示が必須) |
| `--flush` | 操作の合間に、ロード済みのすべてのトランジェントオブジェクトをフラッシュ |
| `--clear` | `TPM2_Clear`、オーナー階層を消去 |
| `--mldsa[=44/65/87]` | Pure ML-DSA の署名/検証 (デフォルトは 65) |
| `--hash-mldsa[=44/65/87]` | HashML-DSA (SHA-256 プリハッシュ) の署名/検証 |
| `--mlkem[=512/768/1024]` | ML-KEM のカプセル化/デカプセル化 |
| `--all` | caps + algs + selftest + getrandom + pcrread + すべての PQC セット |

コマンドは左から右へ順に実行されるため、連結できます。`pqc_ctrl` には `--enable-v185` (または `--enable-pqc`) が必要です。SEALSQ のデバイスを対象にするには `--enable-sealsq` を、fwTPM を対象にするには `--enable-fwtpm --enable-swtpm` を指定してください。

`pqc_ctrl.sh` は、デバイスがすべてのパラメータセットをサポートしている場合に、コマンドセット全体を合否判定付きのスイートとして実行します (`examples/spdm/spdm_test.sh` に倣っています)。状態を変更するステップは `PQC_CTRL_CLEAR=1` によるオプトインであり、スイートが意図せず TPM を変更することはありません。

```sh
./examples/pqc/pqc_ctrl.sh
PQC_CTRL_CLEAR=1 ./examples/pqc/pqc_ctrl.sh   # also extend PCR 16 and run TPM2_Clear
```

!!! warning
    `PQC_CTRL_CLEAR=1` は 1 つではなく 2 つの処理を行います。まず PCR 16 を拡張します。これは PCR をリセットしない限り元に戻せません。次に `TPM2_Clear` を実行し、オーナー階層を消去します。使い捨てのテスト用 TPM、または状態をバックアップ済みのデバイスでのみ使用してください。

### pqc_mssim_e2e

mssim ソケット経由のエンドツーエンドのクライアントテストです。次の 4 つのチェックを順に実行します。

1. ML-KEM-768 の `CreatePrimary`、`Encapsulate`、`Decapsulate`。暗号文が 1088 バイトであること、および 2 つの共有秘密がバイト単位で一致することを検証します。
2. HashML-DSA-65 (SHA-256) の `CreatePrimary`、`SignDigest`、`VerifyDigestSignature`。署名が 3309 バイトであること、および検証チケットのタグが `TPM_ST_DIGEST_VERIFIED` であることを検証します。
3. ML-KEM の `MakeCredential` と `ActivateCredential` のラウンドトリップ。
4. ML-DSA の `Quote`。

```sh
./examples/pqc/pqc_mssim_e2e
```

### mlkem_encap

ML-KEM カプセル化のラウンドトリップです。ML-KEM のプライマリ鍵を作成して `Encapsulate` を実行し、生成された暗号文を `Decapsulate` して、共有秘密が一致することを確認します。

```sh
./examples/pqc/mlkem_encap                # default: ML-KEM-768
./examples/pqc/mlkem_encap -mlkem=512
./examples/pqc/mlkem_encap -mlkem=1024
```

### mldsa_sign

Pure ML-DSA の署名と検証のラウンドトリップです。ML-DSA のプライマリ鍵を作成し、`SignSequenceStart` と `SignSequenceComplete` で固定メッセージに署名します。Pure ML-DSA のシーケンスはストリーミング可能であり、メッセージを `SequenceUpdate` 経由で渡すこともできますが、このサンプルでは署名時にメッセージ全体を Complete のバッファで渡します。続いて `VerifySequenceStart`、`VerifySequenceUpdate`、`VerifySequenceComplete` で検証します。返された検証チケットのタグが `TPM_ST_MESSAGE_VERIFIED` であることを検証します。

```sh
./examples/pqc/mldsa_sign                 # default: ML-DSA-65
./examples/pqc/mldsa_sign -mldsa=44
./examples/pqc/mldsa_sign -mldsa=87
```

### keygen と keyload による PQC 鍵

`examples/keygen/keygen` は、`-rsa`、`-ecc`、`-sym`、`-keyedhash` に加えて、v1.85 の PQC オプションを受け付けます。

```sh
./examples/keygen/keygen keyblob.bin -mldsa=65           # Pure ML-DSA
./examples/keygen/keygen keyblob.bin -hash_mldsa=65      # SHA-256 pre-hash
./examples/keygen/keygen keyblob.bin -mlkem=768          # ML-KEM
```

パラメータセット:

- `-mldsa=44|65|87` (デフォルトは 65)
- `-hash_mldsa=44|65|87` (デフォルトは 65、SHA-256 プリハッシュ)
- `-mlkem=512|768|1024` (デフォルトは 768)

生成されたブロブが `TPM2_Create` と `TPM2_Load` を経由してラウンドトリップできることは、読み込み直すことで確認できます。

```sh
./examples/keygen/keyload keyblob.bin
```

読み込みに成功すると、トランジェント鍵ハンドルが表示されます。完全なマトリクス (3 種類のバリアント × 3 つのパラメータセットで 9 通りの鍵構成。それぞれを keygen と keyload で実行) は、`config.h` で v1.85 が検出された場合に `examples/run_examples.sh` によって実行されます。この汎用スイートは、それぞれ固有の TPM 要件を持つ非 PQC の操作もカバーします。

### パラメータ暗号化のための PQC 鍵

ポスト量子暗号のプライマリ鍵は、TPM 2.0 のパラメータ暗号化セッションの鍵として使用できます。ML-KEM (復号可能) はセッションソルト鍵として、ML-DSA (署名のみ) はセッションバインド鍵として使用されます。このセッションは、RSA や ECC のソルト付きセッションと同様に、コマンドの最初のサイズ付きパラメータを保護します。サンプルが必要とする RSA や ECC のストレージ鍵 (たとえば作成される子鍵の親) は変更されません。

!!! note
    パラメータ暗号化の機密性は、バインドセッションがバインドエンティティの authValue から導出するセッション鍵によって得られます (TPM 2.0 Library Part 1、Salted Session)。署名専用の ML-DSA 鍵はソルトを交換できず、サンプルのバインド authValue は公開された定数であるため、ML-DSA によるバインドだけではセッションのバインドは得られても、バス観測者に対する機密性は得られません。宣伝されている暗号化を実質的なものにするため、ヘルパーはトランジェント SRK も作成し、ML-DSA セッションの非対称ソルトとして使用します。機密性は暗号化されたソルトから得られ、ML-DSA 鍵はバインドを提供します。バインドセッションのみで機密性を確保する実運用の構成では、authValue が秘密であり、平文で送信されていないバインドエンティティを使用する必要があります。

`wrap_test`、`pcr/quote`、`nvram/store`、`nvram/counter` は、`-mlkem[=512|768|1024]` と `-mldsa[=44|65|87]` を受け付けます。`keygen` では、`-mlkem` と `-mldsa` オプションがすでに子鍵のアルゴリズムを選択するため、`-paramkey=mlkem[=...]` と `-paramkey=mldsa[=...]` を使用します。

```sh
./examples/wrap/wrap_test -aes -mlkem=768
./examples/pcr/quote 16 quote.blob -ecc -xor -mldsa=65
./examples/nvram/counter -aes -mldsa=65
./examples/keygen/keygen keyblob.bin -ecc -aes -paramkey=mlkem=768
```

ML-KEM は制限付き復号 (ソルト) 鍵であり、対称アルゴリズムの定義が必要です。サンプルのヘルパーは AES-128-CFB を設定します。これは、対称アルゴリズムを持たない制限付き鍵を TPM が `TPM_RC_SYMMETRIC` で拒否するためです。

### ML-DSA プライマリ鍵を用いた create_primary

`examples/keygen/create_primary` は ML-DSA プライマリ鍵を作成できます。

```sh
./examples/keygen/create_primary -mldsa            # default ML-DSA-65
./examples/keygen/create_primary -mldsa=87 -oh
```

### ポスト量子 TLS 1.3 (ML-KEM と TPM ML-DSA)

これは、サーバーの ML-DSA アイデンティティ鍵が TPM 内にある、完全な TLS 1.3 ハンドシェイクです。サーバーは wolfTPM の crypto コールバックを介して、チップ上で CertificateVerify に署名します。クライアントは ML-KEM 鍵交換を行い、ソフトウェア CA に対してサーバーを検証します。

これには、デバイス鍵 (秘密鍵が TPM 内にある) に対して `wc_MlDsaKey_SignCtx` を crypto コールバックにルーティングする wolfSSL が必要です。この変更は wolfSSL 5.9.4-stable 以降に含まれています。開発スナップショットを使用する場合は、wolfSSL のコミット `6b0c832284286dbaec8e5ab35581ff470e90826b` が含まれている必要があります。以下のコマンドは、このデモのためにツリー内の fwTPM を起動します。

!!! warning
    これはデモです。アイデンティティ鍵は認証なし (空の auth) の決定論的な TPM プライマリ鍵であり、`gen_pqc_certs` とサーバーの双方がオーナー階層から再現できます。プライマリ鍵の鍵素材は、階層シードと作成時の入力から導出され、オブジェクトの auth 値はその導出を変えません。そのため、空でない auth 値やポリシーを追加するだけでは、オーナー階層配下で `CreatePrimary` を認可できる別の呼び出し元が同じ鍵を再作成することを防げません。実運用では、プロビジョニング済みの子オブジェクトまたは永続的なアイデンティティオブジェクトと、管理された階層の認可を組み合わせることを推奨します。クライアントはサーバーのチェーンをデモ CA に対して検証しますが、証明書をホスト名にバインドしません。そのため、デモはデフォルトの localhost に接続し、`-h=` を渡しません。`-h=` を指定すると、`wolfSSL_check_domain_name` を含む厳格な検証が有効になり、このリーフ証明書はそれを満たせません。実運用では、一致する subjectAltName を持つリーフ証明書を発行する必要があります。

関与するプログラムは 3 つです。

- `examples/pqc/gen_pqc_certs` は、ソフトウェアの ML-DSA CA と、サブジェクト鍵が TPM の ML-DSA 鍵であるデバイスのリーフ証明書を作成します。
- `examples/tls/tls_server -mldsa` はその TPM 鍵を再作成し、TLS 1.3 を提供します。
- `examples/tls/tls_client -mldsa` は接続し、ML-KEM 鍵交換を行い、CA を検証します。

```sh
./src/fwtpm/fwtpm_server --clear &

# 1. certificate chain bound to the TPM key (-mldsa must match the server)
./examples/pqc/gen_pqc_certs -mldsa=65

# 2. server (same -mldsa as gen_pqc_certs)
./examples/tls/tls_server -p=11111 -mldsa=65 &

# 3. client (choose the ML-KEM group)
./examples/tls/tls_client -p=11111 -mldsa -group=ML_KEM_768
```

オプション:

- `gen_pqc_certs -mldsa=44/65/87`: ML-DSA パラメータセット。
- `tls_server -p=<port> -mldsa=44/65/87`。
- `tls_client -h=<host> -p=<port> -group=<name>`。`<name>` は `ML_KEM_512/768/1024`、またはハイブリッドの `SECP256R1MLKEM768` / `X25519MLKEM768` です (ハイブリッドには、対応する古典曲線が wolfSSL で有効になっている必要があります)。

ワンショットのエンドツーエンドテストは 3 つすべてを駆動し、ML-KEM グループ、TPM 署名による ML-DSA 認証、CA の検証、アプリケーションデータを検証します。

```sh
ENABLE_PQC_TLS=1 ./examples/run_examples.sh   # includes the PQC TLS matrix
```

## ベンチマーク

`examples/bench/bench` で取得した、SEALSQ QVault TPM シリコン上での ML-DSA と ML-KEM のレイテンシ実測値 (鍵生成、署名、検証、カプセル化、デカプセル化) は、[benchmarks.md](benchmarks.md) に掲載されています。鍵生成は一度だけのプロビジョニングコストです。ML-DSA と ECDSA の数値を比較する前に、それらをどのように取得したかを同ページで確認してください。

## 関連項目

- [benchmarks.md](benchmarks.md)
- [FWTPM.md](fwtpm/overview.md)
- [DEVTPM.md](system-interfaces.md)
- [spdm.md](spdm.md)
