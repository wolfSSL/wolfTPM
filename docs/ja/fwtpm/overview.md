# fwTPM 概要

wolfTPM の fwTPM (fTPM とも呼ばれます) は、wolfCrypt の暗号プリミティブを基盤とするファームウェア TPM 2.0 です。テスト専用のエミュレータではありません。スタンドアロンのサーバープロセス (`fwtpm_server`) として動作するか、組み込みファームウェアイメージにリンクして使用できる、ポータブルな TPM 2.0 コマンドプロセッサです。RSA、ECC、AES、およびすべての機能グループを有効にしたデフォルトビルドでは、TPM 2.0 Revision 1.38 の 112 個のコマンドコードのうち 103 個がディスパッチテーブルに含まれます。Version 185 のポスト量子コマンド 8 個を加えると 111 個になります。カウント方法と、最小限のセルフテストや `SU_STATE` による再開が未対応であることなどの既知の制限については、以下のコマンドカバレッジを参照してください。

fwTPM はテストに使用できるほか、ディスクリート TPM チップが利用できない、または使いたくない環境での本番運用、セキュリティ重視、分離型のデプロイメントにも使用できます。そのようなデプロイメントでは、TPM のセキュリティはそれをホストするプラットフォームに依存します。ファームウェア TPM は、それ自体ではディスクリート TPM チップのような物理的な分離を提供しません。そのため、インテグレーターが分離 (別コア、TrustZone のセキュアワールドなど) を用意し、NV ストレージを保護する必要があります。デフォルトのファイルベース NV ストアは、階層シード、認可値、秘密鍵を平文で保持し、`fwtpm_server` 自体は開発およびテスト用のツールです。また、fwTPM は TPM シリコンのないプラットフォームにポスト量子暗号と SPDM を提供します。

統合モデルの例:

- ディスクリート TPM チップのない**組み込みおよび IoT プラットフォーム** (SPI または I2C の TIS HAL によるベアメタル)
- 別コア上で動作する TPM、TrustZone のセキュアワールド、Linux アプリケーションプロセッサの隣にあるロックステップのリアルタイムコアなどの**分離型デプロイメント**。分離はプラットフォームによって実現され、fwTPM が提供するものではありません。
- TPM に依存するアプリケーションの**開発とテスト** (swtpm や Microsoft TPM シミュレータのドロップイン代替)
- TPM 機能を必要とする **CI/CD パイプライン** (tpm2-tools と互換性のあるソケットトランスポート)
- ハードウェアが利用可能になる前の TPM ワークフローの**プロトタイピング**
- TPM シリコンなしでの**ポスト量子および SPDM の作業** ([ポスト量子サポート](post-quantum.md)と [SPDM レスポンダ](spdm.md)を参照)

## 機能

- デフォルトビルドで Revision 1.38 の 112 個のコマンドコードのうち 103 個をカバーする TPM 2.0 コマンドプロセッサ。制限事項はコマンドカバレッジに記載しています。
- Microsoft TPM シミュレータプロトコルを使用する TCP ソケットトランスポート。wolfTPM のサンプルおよび tpm2-tools と互換性があります。mssim と swtpm の両方の TCTI プロトコルがコマンドポート上で自動検出されます。
- POSIX 共有メモリ上の TIS レジスタレベルトランスポート、またはベアメタル統合向けの SPI もしくは I2C 上の TIS レジスタレベルトランスポート。
- I/O と NV ストレージのための HAL 抽象化により、移植時にコアロジックを変更する必要がありません。[HAL と移植](hal-and-porting.md)を参照してください。
- `--enable-pqc` によるポスト量子暗号: TCG TPM 2.0 Library Specification Version 185 に基づく ML-DSA (FIPS 204) 署名と ML-KEM (FIPS 203) 鍵カプセル化。`--enable-pqc` と `--enable-v185` はプロジェクト全体では別個のモードですが、fwTPM のビルドでは configure が `--enable-pqc` を完全な Version 185 モードに引き上げるため、fwTPM に関しては両者の動作は同じです。`--enable-fwtpm` が両方を備えた wolfCrypt に対してビルドされる場合、configure は PQC を自動検出します。[ポスト量子サポート](post-quantum.md)を参照してください。
- シリコンなしで SPDM スタックをテストするための SPDM 1.3 レスポンダ。[SPDM レスポンダ](spdm.md)を参照してください。
- 制約のあるターゲット向けにビルドを縮小するコンパイル時機能ゲート (`FWTPM_NO_*`)。[ビルド](building.md)を参照してください。

## アーキテクチャ

```
+---------------------+     +-------------------------------+
| wolfTPM Client App  |     |  fwtpm_server (or embedded)   |
| (examples, tests)   |     |                               |
+----------+----------+     |  +-------------------------+  |
           |                |  | Transport Layer         |  |
     TCP (SWTPM protocol)   |  | (socket or TIS)         |  |
     or TIS shared memory   |  +------------+------------+  |
     or SPI/I2C TIS         |               |               |
           |                |  +------------v------------+  |
           +--------------->|  | FWTPM_ProcessCommand    |  |
                            |  | (fwtpm_command.c)       |  |
                            |  +------+-----------+------+  |
                            |         |           |         |
                            |  +------v-----+ +---v------+  |
                            |  | wolfCrypt  | | NV       |  |
                            |  | (RSA, ECC, | | backend  |  |
                            |  |  SHA, HMAC,| | (fwtpm_  |  |
                            |  |  RNG, AES) | |  nv.c)   |  |
                            |  +------------+ +----------+  |
                            +-------------------------------+
```

ソケットトランスポートと TIS トランスポートのどちらも、各コマンドを `FWTPM_ProcessCommand` に渡します。その後、コマンドハンドラが wolfCrypt と NV バックエンドを使用します。この流れは、スタンドアロンサーバーでも組み込み統合でも同じです。

**コンポーネント:**

| ファイル | 役割 |
|------|------|
| `fwtpm_command.c` | TPM 2.0 コマンドプロセッサとディスパッチテーブル |
| `fwtpm_io.c` | トランスポート層: SWTPM TCP ソケットプロトコル (swtpm 構成で有効になります。この構成を使用しないビルドでは TIS パスを使用します) |
| `fwtpm_nv.c` | NV ストレージ: ファイルベース (デフォルト)。HAL で抽象化されており、ライトワンスフラッシュ向けの組み込みアペンドオンリーモードを備えます |
| `fwtpm_tis.c` | TIS レジスタステートマシン (トランスポート非依存) |
| `fwtpm_tis_shm.c` | POSIX 共有メモリとセマフォによる TIS トランスポート |
| `fwtpm_main.c` | サーバーのエントリポイント、CLI 引数の解析 |
| `tpm2_util.c` | 共有ユーティリティ (ハッシュヘルパー、ForceZero、PrintBin) |
| `tpm2_packet.c` | TPM パケットのマーシャルとアンマーシャル |
| `tpm2_param_enc.c` | パラメータ暗号化 (XOR および AES セッション暗号化) |

## サポートされる TPM 2.0 コマンド

このセクションは代表的なコマンドを列挙したもので、網羅的ではありません。`PCR_Event`、`PCR_Allocate`、`ClockRateAdjust`、いくつかのポリシーコマンド、およびアルゴリズムに依存する一部のコマンドなど、サポートされているコマンドの一部は省略しています。ディスパッチテーブルの内訳は後述のコマンドカバレッジにあります。デフォルトのビルド (`FWTPM_NO_*` マクロを設定しない場合) には、以下のすべてのグループが含まれます。ゲートマクロを設定すると、そのグループのコマンドがディスパッチテーブル、`TPM2_GetCapability(TPM_CAP_COMMANDS)`、および `TPM_PT_TOTAL_COMMANDS` のカウントから除外されます。ゲートについては[ビルド](building.md)を参照してください。

### 起動とセルフテスト

| コマンド | 説明 |
|---------|-------------|
| `TPM2_Startup` | TPM を初期化 (SU_CLEAR または SU_STATE) |
| `TPM2_Shutdown` | 状態を保存し、電源オフに備える |
| `TPM2_SelfTest` | 最小限のセルフテスト: SHA-256 の既知解テストと RNG のチェック。ソースコードではこれを仕様非準拠としています。 |
| `TPM2_IncrementalSelfTest` | 空の to-do リストを返すだけの何もしないスタブ |
| `TPM2_GetTestResult` | セルフテストの結果を返す |

### 乱数生成

| コマンド | 説明 |
|---------|-------------|
| `TPM2_GetRandom` | ランダムバイトを生成 (1 回の呼び出しで最大 48) |
| `TPM2_StirRandom` | RNG の状態にエントロピーを追加 |

### ケイパビリティ

| コマンド | 説明 |
|---------|-------------|
| `TPM2_GetCapability` | TPM のプロパティ、アルゴリズム、ハンドルを照会 |

### 鍵管理

| コマンド | 説明 |
|---------|-------------|
| `TPM2_CreatePrimary` | 階層の下にプライマリ鍵を作成 |
| `TPM2_Create` | 親の下に子鍵を作成 |
| `TPM2_CreateLoaded` | 鍵の作成とロードを 1 つのコマンドで実行 |
| `TPM2_Load` | プライベート部とパブリック部から鍵をロード |
| `TPM2_LoadExternal` | 外部 (ソフトウェア) 鍵をロード |
| `TPM2_Import` | 外部でラップされた鍵をインポート |
| `TPM2_Duplicate` | 転送用に鍵をエクスポート (内側と外側のラッピング) |
| `TPM2_Rewrap` | 複製されたオブジェクトを古い親から新しい親へ再ラップ |
| `TPM2_FlushContext` | トランジェントオブジェクトまたはセッションをアンロード |
| `TPM2_ContextSave` | オブジェクトまたはセッションのコンテキストを保存 |
| `TPM2_ContextLoad` | 保存したコンテキストを復元 |
| `TPM2_ReadPublic` | ロード済みの鍵のパブリック領域を読み取り |
| `TPM2_ObjectChangeAuth` | 鍵の認可を変更 |
| `TPM2_EvictControl` | トランジェント鍵を永続化 (または削除) |
| `TPM2_HierarchyControl` | 階層を有効化または無効化 |
| `TPM2_HierarchyChangeAuth` | 階層の認可値を変更 |
| `TPM2_Clear` | ストレージプライマリシードを再生成し、オーナーとエンドースメントの認可およびポリシー状態をリセットして、対象となるオブジェクトを削除予定にする。プラットフォームシードとエンドースメントシードは再生成しない。 |
| `TPM2_ChangePPS` | プラットフォームプライマリシードを置換 |
| `TPM2_ChangeEPS` | エンドースメントプライマリシードを置換 |

### 暗号操作

| コマンド | 説明 |
|---------|-------------|
| `TPM2_Sign` | ロード済みの鍵でダイジェストに署名 |
| `TPM2_VerifySignature` | ロード済みの鍵に対して署名を検証 |
| `TPM2_RSA_Encrypt` | RSA 暗号化 (OAEP、PKCS1) |
| `TPM2_RSA_Decrypt` | RSA 復号 |
| `TPM2_EncryptDecrypt` | 対称鍵による暗号化と復号 |
| `TPM2_EncryptDecrypt2` | 対称鍵による暗号化と復号 (代替) |
| `TPM2_Hash` | ワンショットのハッシュ計算 |
| `TPM2_HMAC` | ワンショットの HMAC 計算 |
| `TPM2_ECDH_KeyGen` | 一時的な ECC 鍵ペアを生成 |
| `TPM2_ECDH_ZGen` | ECDH 共有秘密を計算 |
| `TPM2_ECC_Parameters` | ECC 曲線パラメータを取得 |
| `TPM2_TestParms` | アルゴリズムパラメータのサポートを検証 |

### ハッシュシーケンス

| コマンド | 説明 |
|---------|-------------|
| `TPM2_HashSequenceStart` | ハッシュシーケンスを開始 |
| `TPM2_HMAC_Start` | HMAC シーケンスを開始 |
| `TPM2_SequenceUpdate` | ハッシュまたは HMAC シーケンスにデータを追加 |
| `TPM2_SequenceComplete` | ハッシュまたは HMAC シーケンスを完了して結果を取得 |
| `TPM2_EventSequenceComplete` | ハッシュシーケンスを完了して PCR を拡張 |

### シーリング

| コマンド | 説明 |
|---------|-------------|
| `TPM2_Unseal` | シール済みオブジェクトからデータをアンシール |

### PCR (Platform Configuration Registers)

| コマンド | 説明 |
|---------|-------------|
| `TPM2_PCR_Read` | PCR の値を読み取り |
| `TPM2_PCR_Extend` | ダイジェストで PCR を拡張 |
| `TPM2_PCR_Reset` | リセット可能な PCR をリセット |

### クロック

| コマンド | 説明 |
|---------|-------------|
| `TPM2_ReadClock` | TPM クロックの値を読み取り |
| `TPM2_ClockSet` | TPM クロックを設定 |

### セッションと認可

| コマンド | 説明 |
|---------|-------------|
| `TPM2_StartAuthSession` | HMAC、ポリシー、またはトライアルセッションを作成 |

### ポリシー

| コマンド | 説明 |
|---------|-------------|
| `TPM2_PolicyGetDigest` | 現在のポリシーセッションダイジェストを取得 |
| `TPM2_PolicyRestart` | ポリシーセッションダイジェストをリセット |
| `TPM2_PolicyPCR` | ポリシーを PCR 値にバインド |
| `TPM2_PolicyPassword` | ポリシーにパスワードを含める |
| `TPM2_PolicyAuthValue` | ポリシーに認可値を含める |
| `TPM2_PolicyCommandCode` | ポリシーを特定のコマンドに制限 |
| `TPM2_PolicyOR` | ポリシー分岐の論理和 |
| `TPM2_PolicySecret` | シークレットによる認可 |
| `TPM2_PolicyAuthorize` | 署名鍵でポリシーを承認 |
| `TPM2_PolicyNV` | NV インデックスの比較に基づくポリシー |
| `TPM2_PolicyLocality` | ポリシーを特定のローカリティに制限 |
| `TPM2_PolicySigned` | 外部署名鍵でポリシーを認可 |

### ディクショナリアタック (DA) 保護

| コマンド | 説明 |
|---------|-------------|
| `TPM2_DictionaryAttackParameters` | `maxTries`、`recoveryTime`、`lockoutRecovery` を設定 |
| `TPM2_DictionaryAttackLockReset` | 失敗試行カウンタをリセット (lockoutAuth) |

fwTPM は、TPM 2.0 仕様 (Part 1、Section 19.8) をモデルとしたディクショナリアタック保護を実装しています。DA 保護されたエンティティの認可に失敗すると `failedTries` が増加します。`maxTries` に達すると、TPM は `TPM_RC_LOCKOUT` を返します。`failedTries` は失敗のたびに NV へ永続化されるため、電源の再投入でリセットすることはできません。

クロック HAL が登録されている場合 (`FWTPM_Clock_SetHAL`)、カウンタは `recoveryTime` 秒ごとに 1 回分ずつ自己回復し、非正常シャットダウンでは 1 回分のペナルティが加算されます。クロックのないビルドではどちらも適用されません。永続化された `failedTries` カウンタは自己回復せず、回復は `DictionaryAttackLockReset` または `Clear` のみで行われるため、通常の異常な電源断が積み重なってロックアウトに至ることはありません。

`lockoutAuth` の認可に失敗すると、ロックアウト階層がロックされます。クロック HAL のあるビルドでは、このロックは再起動後も維持され、`lockoutRecovery` 秒後に解除されます。ただし `lockoutRecovery` が 0 の場合 (再起動のみで回復) は除きます。クロックのないビルドでは、`lockoutAuth` の失敗によるロックは起動のたびに解除されます。クロック HAL がある場合、クロック HAL は起動からの経過ミリ秒を報告するため、このタイマーは再起動をまたいだ実時間ではなく、起動後の連続稼働時間を計測します。`lockoutRecovery` より短い間隔で再起動するデバイスでは、実効的な回復期間が延びます。

ゲートは 2 つあり、互いに独立しています。`lockoutAuth` の認可に失敗すると、以降の `lockoutAuth` の使用 (`DictionaryAttackLockReset`、`DictionaryAttackParameters`、およびロックアウト認可の `Clear`) がブロックされます。`maxTries` に達すると、DA 保護されたオブジェクト、NV インデックス、およびバインドされたエンティティの認可がブロックされ、TPM は `TPM_RC_LOCKOUT` を返します。プラットフォーム階層は常に退避経路となります。`TPM2_ClearControl(platformAuth, clearDisable=NO)` に続けて `TPM2_Clear(platformAuth)` を実行すれば、`disableClear` が設定されていても回復できます。`Startup` と `Shutdown` は DA によってゲートされることがないため、ロックアウト中でも再起動すれば常に回復できます。`noDA` が設定されたエンティティ (オブジェクトでは `TPMA_OBJECT_noDA`、NV インデックスでは `TPMA_NV_NO_DA`) はカウンタに影響せず、ロックアウト中も使用可能なままです。

`TPM2_GetCapability(TPM_CAP_TPM_PROPERTIES)` は、`TPM_PT_MAX_AUTH_FAIL`、`TPM_PT_LOCKOUT_INTERVAL`、`TPM_PT_LOCKOUT_RECOVERY`、`TPM_PT_LOCKOUT_COUNTER`、および `TPM_PT_PERMANENT` の `inLockout` ビットを報告します。

永続的なアカウンティングでは、DA 保護された認可の失敗ごとに (および起動ごとの最初の DA 保護された認可の使用時に) NV の FLAGS エントリを書き込みます。カウンタは `maxTries` にある間は増加しませんが、クロックによる自己回復でカウンタが下がることがあり、その場合は同じ起動中にさらに認可失敗と NV 書き込みが発生し得るため、起動ごとの書き込み回数に厳密な上限はありません。フラッシュを使用するターゲットでは、それでも摩耗が増え、認可失敗時のレイテンシが NV に律速されるため、NV バックエンドの選定時にこれを考慮してください。

起動後に DA 保護された (`noDA` でない) 認可を最初に使用すると、TPM によっては `daUsed` フラグを NV に永続化し、書き込み中は `TPM_RC_RETRY` ("同一のコマンドを再送せよ") を返すことがあります。TCG のアーキテクチャでは、これは実装方法の 1 つとして説明されており、すべての TPM に求められる要件ではありません。`FWTPM_DA_USED_RETRY` を指定してビルドすると、この動作をエミュレートし、クライアントの再送およびリトライ処理を検証できます。デフォルトではオフで、DA のアカウンティングと永続化はこの設定に関係なく有効です。`FWTPM_NO_DA` で DA ロジックをすべてコンパイル対象から外せます。

カバレッジ: `tests/fwtpm_unit_tests.c` の DA、noDA、ロックアウト、自己回復、永続化のユニットテスト、`examples/management/da_check` のエンドツーエンドサンプル (破壊的なロックアウトと回復のパスには `-lockout` を追加)、および `FWTPM_DA_USED_RETRY` ビルドに対して `TPM_RC_RETRY` のパスを検証する `tests/fwtpm_da_retry.sh` ハーネス。

### 不揮発性ストレージ (NV)

| コマンド | 説明 |
|---------|-------------|
| `TPM2_NV_DefineSpace` | NV インデックスを作成 |
| `TPM2_NV_UndefineSpace` | NV インデックスを削除 |
| `TPM2_NV_ReadPublic` | NV インデックスのパブリックメタデータを読み取り |
| `TPM2_NV_Write` | NV インデックスにデータを書き込み |
| `TPM2_NV_Read` | NV インデックスからデータを読み取り |
| `TPM2_NV_Extend` | NV インデックスを拡張 (ハッシュ拡張) |
| `TPM2_NV_Increment` | NV カウンタをインクリメント |
| `TPM2_NV_WriteLock` | NV インデックスを書き込みロック |
| `TPM2_NV_ReadLock` | NV インデックスを読み取りロック |
| `TPM2_NV_SetBits` | NV ビットフィールドインデックスにビットを OR |
| `TPM2_NV_ChangeAuth` | NV インデックスの認可値を変更 |

### アテステーションとクレデンシャル

| コマンド | 説明 |
|---------|-------------|
| `TPM2_Quote` | 署名付き PCR クォートを生成 |
| `TPM2_Certify` | ロード済みの鍵を証明 |
| `TPM2_CertifyCreation` | 鍵がこの TPM で作成されたことを証明 |
| `TPM2_GetTime` | TPM クロックの署名付きアテステーション |
| `TPM2_NV_Certify` | NV インデックスの内容を証明 |
| `TPM2_MakeCredential` | 鍵用のクレデンシャルブロブを作成 |
| `TPM2_ActivateCredential` | クレデンシャルブロブをアンラップ |

## コマンドカバレッジ

### 実装済み (Revision 1.38 のコマンドコード 103 個)

このページではコマンド名ではなくコマンドコードを数え、標準の合計から `TPM_CC_Vendor_TCG_Test` を除外しています。Revision 1.38 は 112 個の標準コマンドコードを定義しています。RSA、ECC、AES、およびすべての機能グループを有効にした場合、ディスパッチテーブルにはそのうち 103 個が含まれ、これは Revision 1.38 の約 92% にあたります。Version 185 のポスト量子コマンドがさらに 8 個加わります。エントリ数を 113 にするには、`WOLFTPM_SPDM` (コマンド 1 個、`PolicyTransportSPDM` が追加されます) とテスト専用のベンダーコマンドも必要です。

**コアセット、ゲートされない (36 コマンド):**
Startup, Shutdown, SelfTest, IncrementalSelfTest, GetTestResult, GetRandom, StirRandom, GetCapability, TestParms, PCR_Read, PCR_Extend, PCR_Reset, PCR_Event, PCR_Allocate, PCR_SetAuthPolicy, PCR_SetAuthValue, CreatePrimary, FlushContext, ReadPublic, Clear, ClearControl, ChangeEPS, ChangePPS, HierarchyControl, HierarchyChangeAuth, SetPrimaryPolicy, EvictControl, Create, ObjectChangeAuth, Load, Sign, VerifySignature, StartAuthSession, Unseal, LoadExternal, CreateLoaded

これらはすべてのビルドに含まれます。

**オプションのベンダーコマンド (デフォルトではオフ、`WOLFTPM_FWTPM_TCG_TEST`):**
Vendor_TCG_Test

**アルゴリズムに依存 (`NO_RSA`、`HAVE_ECC`、`NO_AES`):**
RSA_Encrypt, RSA_Decrypt, ECDH_KeyGen, ECDH_ZGen, ECC_Parameters, EC_Ephemeral, ZGen_2Phase, EncryptDecrypt, EncryptDecrypt2

**機能マクロに依存:**

- `FWTPM_NO_POLICY`: PolicyGetDigest, PolicyRestart, PolicyPCR, PolicyPassword, PolicyAuthValue, PolicyCommandCode, PolicyOR, PolicySecret, PolicyAuthorize, PolicyLocality, PolicySigned, PolicyNV, PolicyPhysicalPresence, PolicyCpHash, PolicyNameHash, PolicyDuplicationSelect, PolicyNvWritten, PolicyTemplate, PolicyCounterTimer, PolicyTicket, PolicyAuthorizeNV (21 コマンド)。条件付きの `PolicyTransportSPDM` コマンドもゲートします。
- `FWTPM_NO_NV`: NV_DefineSpace, NV_UndefineSpace, NV_UndefineSpaceSpecial, NV_ReadPublic, NV_Write, NV_Read, NV_Extend, NV_Increment, NV_WriteLock, NV_ReadLock, NV_SetBits, NV_ChangeAuth, NV_GlobalWriteLock (13 コマンド)。ポリシーが有効な場合は PolicyNV と PolicyAuthorizeNV もゲートし、`FWTPM_CTX` からメモリ内の NV インデックススロットを削除します。NV_Certify は `FWTPM_NO_ATTESTATION` に加えて `FWTPM_NO_NV` でもゲートされます。
- `FWTPM_NO_ATTESTATION`: Quote, Certify, CertifyCreation, GetTime, NV_Certify (NV_Certify は `FWTPM_NO_NV` でも削除されます)
- `FWTPM_NO_CREDENTIAL`: MakeCredential, ActivateCredential
- `FWTPM_NO_DA`: DictionaryAttackLockReset, DictionaryAttackParameters (2 コマンド)
- `FWTPM_NO_PARAM_ENC`: コマンドおよびレスポンスパラメータの暗号化と復号を無効にします。セッションは HMAC 認可として引き続き機能しますが、暗号化トランスポートは無効になります。AES-CFB と XOR のパラメータ暗号化を削除することでコードサイズを削減します。
- `FWTPM_NO_KEY_MIGRATION`: Import, Duplicate, Rewrap (3 コマンド)。Create と Load が使用する共有の鍵ヘルパーは残ります。
- `FWTPM_NO_ECDH`: ECDH_KeyGen, ECDH_ZGen, EC_Ephemeral, ZGen_2Phase, ECC_Parameters (5 コマンド)。ECDSA の署名と検証は残ります。`FWTPM_CTX` から `ecEphemeral*` のコミット状態も削除します。
- `FWTPM_NO_HASH_CMDS`: Hash, HMAC, HMAC_Start, HashSequenceStart, SequenceUpdate, SequenceComplete, EventSequenceComplete (7 コマンド)。`WOLFTPM_MLDSA` がビルドされている場合、ML-DSA の検証シーケンスがメッセージを SequenceUpdate 経由でストリーミングするため、SequenceUpdate のみが残ります。SequenceComplete は共有されません。ML-DSA のシーケンスは SignSequenceComplete と VerifySequenceComplete で完了するため、ゲートされたビルドで SequenceComplete を公開すると、決して成功しないコマンドを公開することになります。また、`FWTPM_CTX` からインスタンスごとのハッシュシーケンススロット (`hashSeq[FWTPM_MAX_HASH_SEQ]`) も削除します。
- `FWTPM_NO_CONTEXT`: ContextSave, ContextLoad (2 コマンド)。FlushContext は残ります。`FWTPM_CTX` から起動ごとのコンテキスト保護鍵と保存済みコンテキストのリプレイリストも削除します。
- `FWTPM_NO_SYM_ENCRYPT`: EncryptDecrypt, EncryptDecrypt2 (2 コマンド)。`NO_AES` の内側にネストされます。AES 自体は、セッションパラメータ暗号化、AES-GCM、および (`FWTPM_NO_CONTEXT` も設定されていない場合は) コンテキスト保護のために残ります。
- `FWTPM_NO_CLOCK`: ReadClock, ClockSet, ClockRateAdjust (3 コマンド)。GetTime はこのフラグではなく `FWTPM_NO_ATTESTATION` の対象です。
- `FWTPM_NO_PP`: PolicyPhysicalPresence と物理プレゼンスの強制。物理プレゼンス HAL、プラットフォームラッチ、および `FWTPM_PP_SetHAL` を削除します。

これらのゲートは独立しており、意図的に包括的なマクロは用意されていません。fTPM に不要なグループだけを正確に選択してください。すべてのゲートを適用すると、常に存在する 36 個のコアコマンドと、アルゴリズム構成によって残るコマンドだけが残ります (NV を残すか、`FWTPM_NO_NV` を追加して NV も削除する)。具体的な選択例については、`wolftpm-examples` リポジトリの MicroBlaze V サンプル ([使用方法](usage.md)に記載) を参照してください。

### 未実装コマンド

#### Revision 1.38 ベースライン (未実装のコマンドコード 9 個)

中程度 (処理はやや複雑で、既存のインフラを土台にできる):

| コマンド | 仕様セクション | 難易度 | 備考 |
|---------|-------------|------------|-------|
| `TPM2_SetCommandCodeAuditStatus` | 21.2 | 中 | 監査対象コマンドのリストを管理。コンテキストに監査ビットマップが必要 |
| `TPM2_PP_Commands` | 26.2 | 中 | 物理プレゼンスコマンドのリストを管理。PP コマンドのビットマップが必要 |

高 (複雑な暗号処理または新しいサブシステムが必要):

| コマンド | 仕様セクション | 難易度 | 備考 |
|---------|-------------|------------|-------|
| `TPM2_GetSessionAuditDigest` | 18.5 | 高 | セッション監査ダイジェストに署名。セッション監査の追跡 (セッション内の全コマンドの連続ハッシュ) が必要。新しいサブシステム |
| `TPM2_GetCommandAuditDigest` | 18.6 | 高 | コマンド監査ダイジェストに署名。連続ハッシュを持つコマンド監査ログが必要。新しいサブシステム |
| `TPM2_Commit` | 19.2 | 高 | DAA と匿名アテステーションの一時鍵。複雑な ECC 点演算 (K、L、E の生成)。wolfCrypt での DAA サポートが必要 |
| `TPM2_SetAlgorithmSet` | 26.3 | 高 | ベンダー固有のアルゴリズム設定。実装されることはまれで、TPM_RC_COMMAND_CODE を返してもよい |
| `TPM2_FieldUpgradeStart` | 27.2 | 高 | ファームウェアアップグレードの開始。ベンダー固有で、安全な更新基盤が必要 |
| `TPM2_FieldUpgradeData` | 27.3 | 高 | ファームウェアアップグレードのデータブロック。ベンダー固有 |
| `TPM2_FirmwareRead` | 27.4 | 高 | バックアップ用にファームウェアを読み取り。ベンダー固有 |

#### Revision 1.59 での追加 (新しいコマンドコード 5 個)

`TPM2_MAC` はコマンドコード 0x155 を `TPM2_HMAC` と共有し、`TPM2_MAC_Start` は 0x15B を `TPM2_HMAC_Start` と共有しているため、新しいコードは追加されません。ソースコードには HMAC 形式のみが見られ (CMAC の処理は見つかりませんでした)、対称鍵による MAC 形式がサポートされているかどうかは確認できていません。

| コマンド | 仕様セクション | 難易度 | 備考 |
|---------|-------------|------------|-------|
| `TPM2_MAC` | 15.6 | 中 | ブロック暗号 MAC (CMAC)。HMAC に似ているが対称鍵を使用。wolfCrypt の CMAC が必要 |
| `TPM2_MAC_Start` | 17.3 | 中 | MAC シーケンスを開始。CMAC 向けに HMAC_Start と対をなす |
| `TPM2_CertifyX509` | 18.8 | 高 | 部分的な X.509 証明書を生成。複雑な ASN.1 構築が必要で、呼び出し側が tbsCert テンプレートを提供する。Version 184 で非推奨 |
| `TPM2_AC_GetCapability` | 32.2 | 高 | Version 184 で非推奨。アタッチされたコンポーネントのケイパビリティ照会。ハードウェア固有で、ソフトウェア TPM ではほとんど不要 |
| `TPM2_AC_Send` | 32.3 | 高 | Version 184 で非推奨。アタッチされたコンポーネントへのデータ送信。ハードウェア固有 |
| `TPM2_Policy_AC_SendSelect` | 32.4 | 中 | Version 184 で非推奨。AC_Send 用のポリシー。他のポリシーコマンドと同様 |
| `TPM2_ACT_SetTimeout` | 33.2 | 中 | 認証付きカウントダウンタイマーを設定。ACT の状態とタイマー基盤が必要 |

#### Version 184 での追加 (コマンドコード 9 個、未実装 8 個)

Version 184 では、`CreateLoaded`、`AC_GetCapability`、`AC_Send`、`Policy_AC_SendSelect`、`CertifyX509` が非推奨とされています。`CreateLoaded` はここでは引き続き実装されています。

| コマンド | 仕様セクション | 難易度 | 備考 |
|---------|-------------|------------|-------|
| `TPM2_ECC_Encrypt` | 14.8 | 中 | Part 1 Annex C で定義された TPM 固有の構成 (一時的な ECDH 点、KDF によるマスキング、および完全性データ) を用いる ECC ベースの暗号化。このコマンドではスキームを選択できません。 |
| `TPM2_ECC_Decrypt` | 14.9 | 中 | ECC ベースの復号。ECC_Encrypt と対をなす |
| `TPM2_PolicyCapability` | 23.x | 易 | ポリシーセッションで TPM のケイパビリティ値をアサート |
| `TPM2_PolicyParameters` | 23.x | 易 | ポリシーセッションでコマンドパラメータをアサート |
| `TPM2_SetCapability` | 30.x | 中 | TPM のケイパビリティ設定を変更。プラットフォーム認可が必要 |
| `TPM2_NV_DefineSpace2` | 31.x | 中 | 拡張 NV 領域の定義 (より大きな属性フィールド)。既存の NV_DefineSpace を拡張 |
| `TPM2_NV_ReadPublic2` | 31.x | 易 | 拡張 NV のパブリック読み取り。既存の NV_ReadPublic を拡張 |
| `TPM2_ReadOnlyControl` | 24.x | 易 | TPM の読み取り専用モードを切り替え。単純なフラグ |

#### 条件付きで実装

`TPM2_PolicyTransportSPDM` は、`WOLFTPM_SPDM` が有効な場合は常にハンドラとディスパッチテーブルのエントリを持ち、`FWTPM_NO_POLICY` によって削除されます。未実装ではありません。[SPDM レスポンダ](spdm.md)を参照してください。

### カバレッジのまとめ

8 つの Version 185 PQC コマンド (`TPM2_Encapsulate`、`TPM2_Decapsulate`、`TPM2_SignDigest`、`TPM2_VerifyDigestSignature`、`TPM2_SignSequenceStart`、`TPM2_SignSequenceComplete`、`TPM2_VerifySequenceStart`、`TPM2_VerifySequenceComplete`) は、`--enable-pqc` の下で実装されています。これらのコマンドの PQC 限定の制約については、[ポスト量子サポート](post-quantum.md)を参照してください。

| 仕様バージョン | コマンドコード総数 | 実装済み (デフォルトビルド) | 未実装 | カバレッジ |
|-------------|---------------------|-----------------------------|---------|----------|
| Revision 1.38 | 112 | 103 | 9 | 92% |
| Revision 1.59 | 117 | 103 | 14 | 88% |
| Version 184 | 126 | 103 | 23 | 82% |
| Version 185 | 134 | 111 | 23 | 83% |

実装済みの数は、RSA、ECC、AES、およびすべての機能グループが有効で、SPDM、PQC (Version 185 の行を除く)、およびベンダーテストコマンドが無効であることを前提としています。`WOLFTPM_SPDM` を有効にすると `PolicyTransportSPDM` が加わります (実装済みのコードが 1 個増えます)。Version 185 の行には 8 個の PQC コマンドが含まれます。

既知の制限: `TPM2_SelfTest` は最小限のスモークテストで、`TPM2_IncrementalSelfTest` はスタブです (前述のとおり)。また、`SU_STATE` による再開はサポートされていません (ライフサイクルのセクションを参照)。上記のコマンドカバレッジを、TCG 仕様への完全な準拠を示すものと解釈しないでください。

## 起動とシャットダウンのライフサイクル

1. **初回起動:** `FWTPM_NV_Init` が NV ファイルを見つけられない場合、ランダムな階層シードを生成し、初期状態を保存します。
2. **`TPM2_Startup(SU_CLEAR)`:** トランジェントオブジェクトとセッションをフラッシュし、PCR をリセットします。ほとんどの TPM コマンドよりも前に必要です。`TPM2_GetCapability` は `Startup` の前でも受け付けられます。
3. **通常動作:** コマンドは `FWTPM_ProcessCommand` を通じて処理されます。
4. **`TPM2_Shutdown`:** NV の状態を保存しますが、"started" フラグはクリアしません。TPM は論理的に電源オンのままです。
5. **サーバーの再起動** (プロセスの終了と再起動) が電源の再投入に相当します。`TPM2_Startup` を再度呼び出せるのは、電源の再投入後のみです。

すでに起動済みの TPM に対して `TPM2_Startup` を呼び出すと、`TPM_RC_INITIALIZE` が返されます。

既知の制限: `Startup(SU_STATE)` は、事前に対応する `Shutdown(SU_STATE)` が行われたかどうかを確認せずに受け付けられ、プロセスを再起動すると `FWTPM_CTX` がゼロクリアされて NV に保存された状態だけが再ロードされます。そのため、トランジェントオブジェクトとセッションは再起動をまたいで保持されませんが、仕様に準拠した TPM Resume ではこれらの保持が求められます。揮発性状態のシリアライズと、シャットダウンおよび起動のシーケンスチェックが実装されるまでは、この制限が残ります。

## プライマリ鍵の導出

プライマリ鍵は、この実装に固有の KDFa ベースの式を用いて、階層シードから決定論的に導出されます。同じシード、同じパブリックテンプレート、同じ `sensitiveCreate.data` からは、常に同じ鍵が生成されます。プライマリオブジェクトの作成については、Revision 1.38 の Clause 27 で説明されています。

- **RSA:** 素数 p と q は、ラベル `"RSA p"` と `"RSA q"` を用いた反復的な KDFa、素数判定、CRT 計算によって導出されます。
- **ECC:** 秘密スカラー d は `KDFa(nameAlg, seed, "ECC", hashUnique, counter)` で導出され、公開点は Q = d*G です。
- **KEYEDHASH と SYMCIPHER:** 鍵バイト列は `KDFa(nameAlg, seed, label, hashUnique)` で導出されます。KEYEDHASH では、空でない `sensitiveCreate.data` はそのまま使用され、導出されません。
- **hashUnique:** `H(sensitiveCreate.data || inPublic.unique)` です。`sensitiveCreate.data` は `hashUnique` とキャッシュダイジェストに入力されるため、値が異なれば鍵も異なります。

プライマリ鍵キャッシュ (テンプレートの SHA-256、`FWTPM_MAX_PRIMARY_CACHE` スロット) により、`CreatePrimary` を繰り返し呼び出した場合でも、コストの高い RSA 鍵の再導出を避けられます。

階層シードは `ChangePPS` (プラットフォーム) と `ChangeEPS` (エンドースメント) で管理されます。`Clear` はオーナー (ストレージプライマリ) シードを再生成し、エンドースメントの認可とポリシー状態をリセットしますが、エンドースメントシードとプラットフォームシードは変更しません。エンドースメントシードを置換するには `ChangeEPS` を使用してください。ヌルシードは `Startup(CLEAR)` のたびに再ランダム化されます。ポスト量子のプライマリ鍵については、[ポスト量子サポート](post-quantum.md)を参照してください。

## 関連項目

- [ビルド](building.md)
- [使用方法](usage.md)
- [HAL と移植](hal-and-porting.md)
- [ポスト量子サポート](post-quantum.md)
- [SPDM レスポンダ](spdm.md)
- [ポスト量子 (ライブラリ全体)](../post-quantum.md)
- [SPDM (ライブラリ全体)](../spdm.md)
