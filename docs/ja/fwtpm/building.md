# fwTPM のビルド

このページでは、fwTPM サーバーのビルド方法、それを制御する configure オプションとコンパイル定義、およびサイズや機能を調整するコンパイル時マクロについて説明します。fwTPM とは何かについては、[概要](overview.md)を参照してください。

## 前提条件

wolfSSL は、TPM サポート、keygen、および `WC_RSA_NO_PADDING` を有効にしてビルドする必要があります。

```sh
cd wolfssl
./configure --enable-wolftpm --enable-pkcallbacks --enable-keygen CFLAGS="-DWC_RSA_NO_PADDING"
make
sudo make install
```

## fwTPM サーバーのビルド

**ソケットトランスポート (SWTPM プロトコル、開発向けの既定):**

```sh
cd wolftpm
./configure --enable-fwtpm --enable-swtpm
make
```

これにより `src/fwtpm/fwtpm_server` が生成され、ソケットベースの通信用に `WOLFTPM_SWTPM` を指定して wolfTPM クライアントライブラリがビルドされます。

**TIS および共有メモリトランスポート (fwTPM HAL 統合向け):**

```sh
./configure --enable-fwtpm
make
```

`--enable-swtpm` を省略すると、ビルドでは TIS 共有メモリトランスポート (`WOLFTPM_FWTPM_HAL`、`WOLFTPM_ADV_IO`) が使用され、`fwtpm_tis.c` がサーバーにコンパイルされます。

**fwTPM サーバーのみ (クライアントライブラリとサンプルなし):**

```sh
./configure --enable-fwtpm-only --enable-swtpm
make
```

これは `fwtpm_server` バイナリのみをビルドし、`libwolftpm`、サンプル、テストをスキップします。TPM サーバーだけが必要な組み込みターゲットで便利です。

**デバッグビルド:**

```sh
./configure --enable-fwtpm --enable-swtpm --enable-debug
make
```

## ビルド成果物

| 成果物 | 説明 |
|----------|-------------|
| `src/fwtpm/fwtpm_server` | スタンドアロンの fwTPM サーバーバイナリ |
| `src/.libs/libwolftpm.*` | wolfTPM クライアントライブラリ |

## 主要なビルドフラグ

| configure オプション | 効果 |
|-----------------|--------|
| `--enable-fwtpm` | `fwtpm_server` バイナリをビルドします (クライアントライブラリとあわせて) |
| `--enable-fwtpm-only` | `fwtpm_server` のみをビルドします (クライアントライブラリ、サンプル、テストなし) |
| `--enable-swtpm` | SWTPM の TCP ソケットトランスポートを使用します (ポート 2321 と 2322) |
| `--enable-fwtpm-nv-appendonly` | 書き込み一回限りのフラッシュ移植向けの追記専用 NV ジャーナル (既定では無効) |
| `--enable-pqc` (別名 `--enable-v185`) | TPM 2.0 v1.85 のポスト量子サポート ([ポスト量子サポート](post-quantum.md)を参照) |
| `--enable-spdm` | SPDM レスポンダ (`--enable-tcg` または `--enable-psk` とあわせて使用。[SPDM レスポンダ](spdm.md)を参照) |
| `--enable-fuzz` | ファジング用ビルド |
| `--enable-debug` | デバッグログを有効にします |

| コンパイル定義 | 設定元 |
|---------------|--------|
| `WOLFTPM_FWTPM` | `fwtpm_server` ターゲットに対してのみ自動的に設定されます |
| `WOLFTPM_SWTPM` | `--enable-swtpm` |
| `WOLFTPM_FWTPM_HAL` | `--enable-swtpm` を指定しない `--enable-fwtpm` |
| `WOLFTPM_FWTPM_TIS` | `--enable-swtpm` を指定しない `--enable-fwtpm` |
| `WOLFTPM_ADV_IO` | `WOLFTPM_FWTPM_HAL` とあわせて設定されます |
| `WOLFTPM_FWTPM_NV_APPEND_ONLY` | `--enable-fwtpm-nv-appendonly` (CMake では `WOLFTPM_FWTPM_NV_APPEND_ONLY=yes`) |
| `WOLFTPM_FWTPM_TCG_TEST` | 手動で設定 (`CFLAGS=-DWOLFTPM_FWTPM_TCG_TEST`)。既定では無効 |

既定ではベンダーコマンドは登録されません。オプションの `TPM2_Vendor_TCG_Test` (`0x20000000`) エコーコマンドをコンパイルして組み込むには、`WOLFTPM_FWTPM_TCG_TEST` を定義します。

## コマンドコードの検証

有効なコマンドコードは、16 ビットのインデックスと、ベンダーコマンドの場合の V ビット (`CC_VEND`、ビット 29) のみを持ちます。その他の予約ビットが設定されているコードや、ディスパッチテーブルにないコードは、`TPM_RC_COMMAND_CODE` で拒否されます。`TPM2_GetCapability(TPM_CAP_COMMANDS)` は、正しい `TPMA_CC` 値 (インデックス、ハンドル属性、V ビットで、コマンドコード順) を返します。

## 設定マクロ

すべてのマクロはコンパイル時に上書きできます (例: `-DFWTPM_MAX_OBJECTS=8`)。

| マクロ | 既定値 | 説明 |
|-------|---------|-------------|
| `FWTPM_MAX_COMMAND_SIZE` | 4096 | コマンドおよびレスポンスバッファの最大サイズ (バイト) |
| `FWTPM_MAX_RANDOM_BYTES` | 48 | `GetRandom` 1 回あたりの最大バイト数 |
| `FWTPM_MAX_OBJECTS` | 3 | 同時にロードできるトランジェントオブジェクトの最大数 |
| `FWTPM_MAX_PERSISTENT` | 8 | 永続オブジェクトの最大数 (`EvictControl` 経由) |
| `FWTPM_MAX_PRIVKEY_DER` | 1280 (`NO_RSA` の場合は 256) | DER エンコードされた秘密鍵の最大サイズ (バイト) |
| `FWTPM_MAX_HASH_SEQ` | 4 | 同時に実行できるハッシュおよび HMAC シーケンスの最大数 |
| `FWTPM_MAX_PRIMARY_CACHE` | 4 | 階層とテンプレートごとにキャッシュされるプライマリ鍵の数 |
| `FWTPM_MAX_SESSIONS` | 4 | 同時に実行できる認可セッションの最大数 |
| `FWTPM_MAX_NV_INDICES` | 16 | NV RAM インデックススロットの最大数。`FWTPM_NO_NV` の場合は `FWTPM_CTX` から省かれます |
| `FWTPM_MAX_NV_DATA` | 2048 | NV インデックスごとの最大データ量 (バイト) |
| `FWTPM_DA_DEFAULT_MAX_TRIES` | 32 | ロックアウトに至る DA の認証失敗回数 |
| `FWTPM_DA_DEFAULT_RECOVERY` | 600 | DA の自己回復間隔 (1 回あたりの秒数) |
| `FWTPM_DA_DEFAULT_LOCKOUT_RECOVERY` | 86400 | lockoutAuth の回復時間 (秒) |
| `FWTPM_DA_MAX_TRIES_LIMIT` | 0xFFFF | 再生された `maxTries` または `failedTries` の上限クランプ値 |
| `FWTPM_MAX_DATA_BUF` | 1024 | HMAC、ハッシュ、一般データ用の内部バッファ |
| `FWTPM_MAX_PUB_BUF` | 512 | 公開領域と署名用の内部バッファ |
| `FWTPM_MAX_DER_SIG_BUF` | 256 | DER 署名と ECC 点用の内部バッファ |
| `FWTPM_MAX_ATTEST_BUF` | 1024 | アテステーションのマーシャリング用の内部バッファ |
| `FWTPM_MAX_CMD_AUTHS` | 3 | 1 コマンドあたりの認可セッションの最大数 (TPM 仕様上の厳密な上限) |
| `FWTPM_MAX_SENSITIVE_SIZE` | `FWTPM_MAX_PRIVKEY_DER + 128` | マーシャリングされるセンシティブ領域の最大サイズ (秘密鍵、認証値、ナンスの余裕分を含む) |
| `FWTPM_MAX_SIGN_SEQ` | 4 | 同時に実行できる v1.85 PQC の署名および検証シーケンスの最大数 |
| `FWTPM_MAX_SYM_KEY_SIZE` | 32 | 対称鍵バッファ (AES-256 に合わせたサイズ) |
| `FWTPM_MAX_HMAC_KEY_SIZE` | 64 | HMAC 鍵バッファ (SHA-512 のブロックに合わせたサイズ) |
| `FWTPM_MAX_HMAC_DIGEST_SIZE` | 64 | HMAC 出力バッファ (SHA-512 に合わせたサイズ) |
| `FWTPM_CMD_PORT` | 2321 | 既定の TCP コマンドポート |
| `FWTPM_PLAT_PORT` | 2322 | 既定の TCP プラットフォームポート |
| `FWTPM_NV_FILE` | `"fwtpm_nv.bin"` | 既定の NV ストレージファイルパス |
| `FWTPM_NV_MAX_WRITE_ALIGN` | 64 | 追記専用のプログラム単位の最大バイト数 (HAL の `writeAlign` の上限)。`WOLFTPM_FWTPM_NV_APPEND_ONLY` が設定されている場合、保留中の単位を保持するバッファのサイズを決定します |
| `FWTPM_PCR_BANKS` | 2 | PCR バンクの数 (SHA-256 と SHA-384) |
| `FWTPM_TIS_BURST_COUNT` | 64 | TIS FIFO のバーストカウント (1 回の転送あたりのバイト数) |
| `FWTPM_TIS_FIFO_SIZE` | 4096 | TIS のコマンドおよびレスポンス FIFO のサイズ |

### スタックとヒープの制御

| マクロ | 効果 |
|-------|--------|
| `WOLFTPM_SMALL_STACK` | 大きなスタックオブジェクトにヒープ割り当てを使用します |
| `WOLFTPM2_NO_HEAP` | ヒープ割り当てを禁止します (すべてスタック) |

!!! note
    `WOLFTPM_SMALL_STACK` と `WOLFTPM2_NO_HEAP` は同時に指定できません。両方を定義するとコンパイルエラーになります。

### v1.85 の組み込み RAM への影響

`--enable-pqc` (または `--enable-v185`) を有効にすると、PQC の鍵と署名のサイズに対応するため、いくつかの内部バッファが拡大されます。既定値は、wolfCrypt のビルド時に有効になっている ML-DSA と ML-KEM のパラメータセット (`WOLFSSL_NO_ML_DSA_44/65/87`、`WOLFSSL_NO_KYBER512/768/1024`) に基づいて、コンパイル時に自動的に縮小されます。小さいパラメータセットのみを有効にしたボードでは、ボードごとの上書きなしで、より小さいバッファになります。

**有効なパラメータセット別のバッファサイズ:**

| マクロ | クラシカル | MLDSA-44 + MLKEM-512 | MLDSA-65 + MLKEM-768 | MLDSA-87 + MLKEM-1024 |
|-------|-----------|----------------------|----------------------|------------------------|
| `FWTPM_TIS_FIFO_SIZE`     | 4096 | 4096 | 8192 | 8192 |
| `FWTPM_MAX_COMMAND_SIZE`  | 4096 | 4096 | 8192 | 8192 |
| `FWTPM_MAX_PUB_BUF`       | 512  | 1440 | 2080 | 2720 |
| `FWTPM_MAX_DER_SIG_BUF`   | 256  | 2548 | 3437 | 4755 |
| `FWTPM_MAX_KEM_CT_BUF`    | n/a  | 832  | 1152 | 1632 |

サイズ決定のロジックは、`wolftpm/fwtpm/fwtpm.h` (定数 `FWTPM_MAX_MLDSA_SIG_SIZE`、`FWTPM_MAX_MLDSA_PUB_SIZE`、`FWTPM_MAX_MLKEM_CT_SIZE`、`FWTPM_MAX_MLKEM_PUB_SIZE`) と `wolftpm/fwtpm/fwtpm_tis.h` (FIFO サイズ) にあります。ML-DSA の定数は wolfCrypt の `WC_MLDSA_{44,65,87}_*_SIZE` マクロから取得されます。ML-KEM の定数は FIPS 203 の仕様値です。これは、wolfCrypt の `WC_ML_KEM_*_SIZE` マクロをプリプロセッサで評価できないためです。

FIFO とコマンドバッファの 8192 への拡大は、MLDSA-65 または MLDSA-87 が有効な場合にのみ適用されます。これらの署名は、TPM ヘッダーを含めると 4096 バイトのレスポンスに収まらないためです。MLDSA-44 のみ、または MLKEM のみの v1.85 ビルドは 4096 のままです。

**デプロイごとの上書き:** 上記のすべてのマクロは引き続き `#ifndef` で保護されているため、自動的な既定値がワークロードに合わない場合、ボードごとにコンパイルラインで個別に上書きできます (例: `-DFWTPM_TIS_FIFO_SIZE=2048`)。

**ヒープとスタック:** `WOLFTPM_SMALL_STACK` を指定してビルドすると、呼び出しごとの大きなバッファがスタックから `XMALLOC` および `XFREE` の領域に移されます。PQC のパスはすでに、このフラグに従う `FWTPM_DECLARE_BUF` と `FWTPM_ALLOC_BUF` を使用しているため、ソースの変更は不要です。`WOLFTPM2_NO_HEAP` もサポートされていますが、スタックのコストをすべて負担することになるため、可能な限り小さい PQC パラメータセットと組み合わせてください。

### アルゴリズム機能マクロ

これらのマクロは、wolfCrypt の既存のコンパイル時オプションを利用して、`fwtpm_server` で利用できる暗号アルゴリズムを制御します。アルゴリズムを無効にすると、対応する TPM コマンドはビルドから除外されます。

| マクロ | 既定値 | 効果 |
|-------|---------|--------|
| `NO_RSA` | 未定義 | RSA の鍵生成、署名、検証、`RSA_Encrypt`、`RSA_Decrypt` を除外します |
| `HAVE_ECC` | 定義済み | ECC の鍵生成、署名、検証、`ECDH_KeyGen`、`ECDH_ZGen`、`ECC_Parameters` を有効にします |
| `HAVE_ECC384` | 定義済み | P-384 曲線のサポートを有効にします |
| `HAVE_ECC521` または `HAVE_ALL_CURVES` | ビルドに依存 | `MAX_ECC_KEY_BITS >= 521` により 66 バイトの TPM ECC フィールドが提供される場合に、P-521 を有効にします |
| `ECC_MIN_KEY_SZ` | wolfCrypt が定義 | 小さい曲線を `ECC_Parameters` と `TPM_CAP_ECC_CURVES` から除外します |
| `NO_AES` | 未定義 | `EncryptDecrypt`、`EncryptDecrypt2`、AES によるパラメータ暗号化を除外します |
| `WOLFSSL_SHA384` | 定義済み | SHA-384 の PCR バンクを有効にします |

アルゴリズムを無効にすると、そのアルゴリズムのみを使用するコマンドは、コンパイル時にディスパッチテーブルから削除されます。複数のアルゴリズムをサポートするコマンド (たとえば `CreatePrimary` や `Sign`) は引き続き利用できますが、無効にしたアルゴリズムタイプに対しては `TPM_RC_ASYMMETRIC` を返します。

### TPM 機能グループマクロ

これらの fwTPM 固有のマクロは、TPM 2.0 の機能グループ全体を無効にして、リソースの限られたターゲットでコードサイズを削減します。

| マクロ | 既定値 | 除外されるコマンド |
|-------|---------|-------------------|
| `FWTPM_NO_ATTESTATION` | 未定義 | `Quote`、`Certify`、`CertifyCreation`、`GetTime`、`NV_Certify` |
| `FWTPM_NO_NV` | 未定義 | `NV_DefineSpace`、`NV_UndefineSpace`、`NV_ReadPublic`、`NV_Write`、`NV_Read`、`NV_Extend`、`NV_Increment`、`NV_WriteLock`、`NV_ReadLock`、`NV_Certify`。また、メモリ上の NV インデックススロットを `FWTPM_CTX` から削除します |
| `FWTPM_NO_POLICY` | 未定義 | `PolicyGetDigest`、`PolicyRestart`、`PolicyPCR`、`PolicyPassword`、`PolicyAuthValue`、`PolicyCommandCode`、`PolicyOR`、`PolicySecret`、`PolicyAuthorize`、`PolicyNV` |
| `FWTPM_NO_CREDENTIAL` | 未定義 | `MakeCredential`、`ActivateCredential` |
| `FWTPM_NO_DA` | 未定義 | `DictionaryAttackParameters`、`DictionaryAttackLockReset`、およびすべてのロックアウト処理 |
| `FWTPM_NO_PARAM_ENC` | 未定義 | セッションにおけるコマンドおよびレスポンスのパラメータ暗号化 (XOR と AES-CFB) のサポート |
| `FWTPM_NO_KEY_MIGRATION` | 未定義 | `Import`、`Duplicate`、`Rewrap` |
| `FWTPM_NO_ECDH` | 未定義 | `ECDH_KeyGen`、`ECDH_ZGen`、`EC_Ephemeral`、`ZGen_2Phase`、`ECC_Parameters` (ECDSA の署名と検証は維持されます)、および `FWTPM_CTX` 内の `ecEphemeral*` コミット状態 |
| `FWTPM_NO_HASH_CMDS` | 未定義 | `Hash`、`HMAC`、`HMAC_Start`、`HashSequenceStart`、`SequenceUpdate`、`SequenceComplete`、`EventSequenceComplete`、および `FWTPM_CTX` 内のハッシュシーケンススロット |
| `FWTPM_NO_CONTEXT` | 未定義 | `ContextSave`、`ContextLoad` (`FlushContext` は維持されます)、および `FWTPM_CTX` 内の起動ごとのコンテキスト保護鍵と保存済みコンテキストのリプレイリスト |
| `FWTPM_NO_SYM_ENCRYPT` | 未定義 | `EncryptDecrypt`、`EncryptDecrypt2` |
| `FWTPM_NO_CLOCK` | 未定義 | `ReadClock`、`ClockSet`、`ClockRateAdjust` |

コマンドグループを削除すると、ディスパッチテーブルから導出される `TPM2_GetCapability(TPM_CAP_COMMANDS)` の通知と `TPM_PT_TOTAL_COMMANDS` の数からも、そのグループが削除されます。`WOLFTPM_MLDSA` をビルドする場合、ML-DSA の検証シーケンスがメッセージを `SequenceUpdate` 経由でストリーミングするため、`FWTPM_NO_HASH_CMDS` の下でも `SequenceUpdate` のみは維持されます。`SequenceComplete` は共有されません (ML-DSA のシーケンスは `TPM2_SignSequenceComplete` と `TPM2_VerifySequenceComplete` で完了します)。そのため、決して成功しないコマンドとして通知されることがないよう、他のハッシュコマンドとともに除外されます。

`FWTPM_DA_USED_RETRY` マクロ (既定では無効) は、コマンドを削除しません。これを有効にすると、起動後に DA で保護された認証が最初に使われたとき、サーバーは `TPM_RC_RETRY` を返し、実際の TPM が `daUsed` を永続化する動作をエミュレートします。[概要](overview.md)の Dictionary Attack Protection を参照してください。

**最小構成のビルド例。** すべてをまとめて無効にするマクロはありません。削除するコマンドグループを明示的に選択することで、それぞれを意図的な選択にします。たとえば、小規模な ECC 専用の署名および NV 対応 fTPM をビルドする場合 (この設定ではアテステーションを削除し、`Sign`、`VerifySignature`、PCR、NV を維持します):

```sh
./configure --enable-fwtpm --enable-swtpm \
    CFLAGS="-DNO_RSA \
        -DFWTPM_NO_POLICY -DFWTPM_NO_ATTESTATION -DFWTPM_NO_CREDENTIAL \
        -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC -DFWTPM_NO_KEY_MIGRATION \
        -DFWTPM_NO_ECDH -DFWTPM_NO_HASH_CMDS -DFWTPM_NO_CONTEXT \
        -DFWTPM_NO_SYM_ENCRYPT -DFWTPM_NO_CLOCK"
```

この設定でも、コアとなる fTPM の機能は維持されます: `Startup`、`Shutdown`、`SelfTest`、`GetRandom`、`GetCapability`、`PCR_*` コマンド、`Create`、`CreatePrimary`、`Load`、`ReadPublic`、`FlushContext`、`Sign`、`VerifySignature`、`NV_*` コマンド、およびセッションのサポート (`StartAuthSession` と `Unseal`)。NV も削除するには `-DFWTPM_NO_NV` を追加し、上記の `-DFWTPM_NO_*` のいずれかを外すと、そのグループを維持できます。この ECC 専用ビルドは、リソースの限られた FPGA 上でソフトコア fTPM として動作できるほど小さくなります (`wolftpm-examples` リポジトリの MicroBlaze V の例を参照してください。ECC 専用の fTPM がオンチップメモリ約 192 KB に収まります)。

**依存関係:**

- `FWTPM_NO_NV` は、`FWTPM_NO_ATTESTATION` が設定されていなくても `NV_Certify` を削除します。
- `NO_RSA` は、RSA によるアテステーション署名が使えないことを意味します。ECC のみのアテステーションは `HAVE_ECC` で引き続き動作します。

## 関連項目

- [概要](overview.md)
- [使い方](usage.md)
- [HAL と移植](hal-and-porting.md)
- [ポスト量子サポート](post-quantum.md)
- [SPDM レスポンダ](spdm.md)
