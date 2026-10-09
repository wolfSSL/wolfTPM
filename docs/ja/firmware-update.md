# ファームウェアアップデート

wolfTPM は、一部の TPM 2.0 モジュールのファームウェアを更新できます。`--enable-firmware` を指定して configure すると、サンプルとライブラリのサポートが有効になります。サポート対象は次のとおりです。

- Infineon SLB9672 (SPI) および SLB9673 (I2C) TPM 2.0 モジュール。Infineon はファームウェアアップデートをオープンソース化しています。
- STMicroelectronics ST33KTPM TPM 2.0 モジュール。第 1 世代ファームウェア (RSA 署名付きマニフェスト)、512 未満の第 9 世代ファームウェア (ECDSA 署名付きマニフェスト)、512 以上の第 9 世代ファームウェア (LMS 署名が必須) をサポートします。

ファームウェアアップデート用のプログラムは `examples/firmware/` にあります: `ifx_fw_extract.c`、`ifx_fw_update.c`、`st33_fw_update.c`、およびポリシーヘルパーの `firmware_policy.c` です。

## Infineon ファームウェア (抽出とアップデート)

### ファームウェアの抽出

Infineon はファームウェアを .bin ファイル (例: `TPM20_15.23.17664.0_R1.BIN`) としてリリースします。この .bin には、16 バイトの GUID ヘッダー、キーグループごとの 1 つ以上のマニフェスト、およびファームウェアが含まれます。一般的なマニフェストは 3KB、ファームウェアは 920KB です。

ホスト側ツール `ifx_fw_extract` は、TPM のアップグレードに必要なマニフェストとファームウェアのデータファイルを抽出します。

```sh
# Build host tool
make

# Help
./ifx_fw_extract --help
Usage:
  ifx_fw_extract <fw-file>
  ifx_fw_extract <fw-file> <keygroup_id> <manifest-file> <data-file>

# Find key groups in .bin
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007

# Extract manifest and firmware data files for key group
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN 7 TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007
Chosen group found: 00000007
Manifest size is 3224
Data size is 934693
Writing TPM20_26.13.17770.0_R1.MANIFEST
Writing TPM20_26.13.17770.0_R1.DATA
```

### ファームウェアのアップデート

`ifx_fw_update` ツールは、マニフェスト (ヘッダー) とファームウェアデータファイルを使用します。

TPM にはキーグループ ID を取得するためのベンダー機能があります。この値は `wolfTPM2_GetCapabilities` を呼び出すと `WOLFTPM2_CAPS.keyGroupId` に格納されます。この値は、抽出ツールに指定した `keygroup_id` と一致する必要があります。

```sh
# Help
./ifx_fw_update --help
Infineon Firmware Update Usage:
        ./ifx_fw_update (get info)
        ./ifx_fw_update --abandon (cancel)
        ./ifx_fw_update --policytest (safe policy auth self-test)
        ./ifx_fw_update [policy opts] <manifest_file> <firmware_file>
        ./ifx_fw_update <manifest_file> <firmware_file> (default auth)
Policy options (caller-supplied authorization):
        --policy    provision+satisfy a PolicyCommandCode
        --policyor  provision+satisfy a PolicyOR (multi-branch)
        --sha256|--sha384|--sha512  policy hash (default SHA-256)

# Run without arguments to display the current firmware information,
# including key group id and operational mode
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)

# Run with manifest and firmware files
./ifx_fw_update TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Infineon Firmware Update Tool
	Manifest File: TPM20_26.13.17770.0_R1.MANIFEST
	Firmware File: TPM20_26.13.17770.0_R1.DATA
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
TPM2_FlushContext: Closed handle 0x3000000
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
Firmware manifest chunk 1024 offset (0 / 3224), state 1
Firmware manifest chunk 1024 offset (1024 / 3224), state 2
Firmware manifest chunk 1024 offset (2048 / 3224), state 2
Firmware manifest chunk 152 offset (3072 / 3224), state 0
Firmware data chunk offset 0
Firmware data chunk offset 1024
Firmware data chunk offset 2048
Firmware data chunk offset 3072
...
Firmware data chunk offset 932864
Firmware data chunk offset 933888
Firmware data done
Mfg IFX (1), Vendor , Fw 0.0 (0x0)
Operational mode: After finalize or abandon, reboot required (0x4)
KeyGroupId 0x7, FwCounter 1253 (254 same)
TPM2_Shutdown failed 304: Unknown

# Reset or power cycle TPM
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1253 (254 same)
```

## ST33 ファームウェアアップデート

このサンプルを有効にするには、`--enable-st33 --enable-firmware` を指定してビルドします。

### ファームウェア形式の自動検出

ST33KTPM のファームウェアアップデートは、TPM のファームウェアバージョンから必要な形式を検出します。マニフェスト (blob0) は 33 バイトの固定ヘッダーに、ファームウェアダイジェストとそれに対する署名が続く構造のため、そのサイズは各世代が署名に使用するアルゴリズムによって決まります。

- 第 1 世代 (メジャーバージョン 1、例: 1.257 や 1.771): 非 LMS 形式。
    - マニフェストサイズ: 321 バイト (SHA-256 ダイジェスト、RSAPSS-2048 署名)。
    - マイナーバージョンがいくら大きくなっても、常に非 LMS です。
- 512 未満の第 9 世代 (例: 9.257): 非 LMS 形式。
    - マニフェストサイズ: 177 バイト (SHA-384 ダイジェスト、ECDSA P-384 署名)。
- 512 以上の第 9 世代 (例: 9.512): LMS (Leighton-Micali Signature) 形式。
    - マニフェストサイズ: 2697 バイト (埋め込みの LMS 署名を含む)。

LMS の要件は第 9 世代のルールであるため、TPM の capabilities から `fwVerMajor` と `fwVerMinor` の両方を参照します。このサンプルは、判定結果をファイル自体でも確認します。blob0 以降はすべて `[type][length]` レコードの連鎖で、ファイルの終端でちょうど終わります。そして、正しいマニフェストサイズだけが最終バイトに一致します。形式を手動で選択する必要はありません。

### パーツの識別

ST33TPHF2X で `TPM_PT_VENDOR_STRING_1..4` が何を返すかは、ファームウェアによって異なります。初期の 1.x ファームウェアはテキストではなくバイナリを返すため、`Vendor` フィールドは空で表示されます。後期の 1.x ファームウェアは ASCII (例: `ST33TPHF2XSPI`) を返します。この変更はファームウェア 1.771 では存在し、1.258 では存在しません。どのファームウェアで導入されたかは不明です。いずれの場合も、ファームウェアのメジャーバージョンが信頼できる識別子であり、パーツとインターフェースのラインに対応します。

| `fwVerMajor` | パーツライン | ファームウェアイメージの例 |
| --- | --- | --- |
| 1 | ST33TPHF2X、SPI ファームウェアライン | `TPM_ST33TPHF2XSPI_00010301.fi` |
| 2 | ST33TPHF2X、I2C ファームウェアライン | `TPM_ST33TPHF2XI2C_00020200.fi` |
| 9 | ST33KTPM2X | `TPM_ST33KTPM2X_00090200_V1.fi` |
| 10 (`0x000a`) | ST33KTPM2A | `TPM_ST33KTPM2A_000a0200.fi` |
| 11 (`0x000b`) | ST33KTPMQ | (手元になし) |

マニフェストヘッダーにも同じバージョンが含まれます。ゼロバイトに続いて、イメージがアップグレード先とするファームウェアバージョンが `TPM_PT_FIRMWARE_VERSION_1` のレイアウトで格納されています (`00 | 00 02 02 00` は 2.512 を表します)。`st33_fw_update` は両方を表示し、メジャーバージョンが実行中のパーツと一致しないイメージは拒否します。

ST33 のファームウェアラインとファームウェアバージョンの関係については、[Supported hardware](supported-hardware.md) を参照してください。

### フィールドアップグレードのコマンドコード

ST33 は、2 組のコマンドコードのいずれかでフィールドアップグレードを実装しています。誤った組を使用すると、マニフェストが解析される前に `TPM_RC_COMMAND_CODE` (`0x143`) が返されます。

| 組 | Start | Data |
| --- | --- | --- |
| 標準 TCG | `TPM_CC_FieldUpgradeStart` (`0x0000012F`) | `TPM_CC_FieldUpgradeData` (`0x00000141`) |
| ST33KTPM ベンダー | `0x2000030C` | `0x2000030D` |

wolfTPM は、2 つの start コードについて `TPM_CAP_COMMANDS` を照会し、TPM がどちらの組を実装しているかを問い合わせます。これは確実な方法であり、パーツの対応表を必要としません。一方、ST 自身のリファレンスツールは、バージョン番号から組を推定します (実行中のファームウェアのマイナーバージョンが 256 未満の場合、またはイメージがファームウェア第 2 世代を対象とする場合は標準コード)。wolfTPM は、TPM が応答しない場合 (ファームウェアアップグレードモードに入った後がこれに該当します) や、両方の組が列挙された場合にのみ、同じルールである `wolfTPM2_ST33_FwUpgradeCommands()` にフォールバックします。

このプローブは重要です。ファームウェア 11.1 の ST33KTPMQ は、マイナーバージョンが 256 未満であるにもかかわらずベンダーの組しか実装していないため、バージョンのルールだけでは誤ったコードが選ばれてしまいます。

手動で選択する必要はありません。呼び出し側が用意したポリシーを使用する場合、`PolicyCommandCode` は実際に送信される start コードにバインドされ、`st33_fw_update` はコードが TPM から取得されたものか推定されたものかを報告します。

ファームウェアファイルを指定せずに `st33_fw_update` を実行すると、接続されているパーツが 4 つのコードのうちどれを実装しているかも、`TPM_CAP_COMMANDS` から読み取って報告します。これは読み取り専用であり、新しいパーツで `TPM_RC_COMMAND_CODE` が発生した場合の最も手早い診断方法です。

```sh
./st33_fw_update
...
Field upgrade command set:
	0x0000012f FieldUpgradeStart       (standard): implemented
	0x00000141 FieldUpgradeData        (standard): implemented
	0x2000030c FieldUpgradeStartVendor (ST33KTPM): not implemented
	0x2000030d FieldUpgradeDataVendor  (ST33KTPM): not implemented
```

既知のファミリー以外のファームウェアメジャーバージョンは、推測せずに不明として扱われます。その場合、マニフェストサイズは断定されず、ツールはサイズをイメージから取得すると報告し、`st33_detect_blob0` のブロックチェーン検証がファイル自体から実際のサイズを確定します。これにより、ST33KTPMQ のような新しいラインのパーツが、該当しないルールを理由にイメージを拒否されることはありません。

### ファームウェアのアップデート

`st33_fw_update` ツールはファームウェア形式を自動的に検出します。

```sh
# Help
./st33_fw_update --help
ST33 Firmware Update Usage:
	./st33_fw_update (get info)
	./st33_fw_update --abandon (cancel)
	./st33_fw_update --policytest (safe policy auth self-test)
	./st33_fw_update [policy opts] <firmware.fi>
	./st33_fw_update <firmware.fi> (default password auth)
Policy options (caller-supplied authorization):
	--policy    provision+satisfy a PolicyCommandCode
	--policyor  provision+satisfy a PolicyOR (multi-branch)
	--sha256|--sha384|--sha512  policy hash (default SHA-256)

Firmware format is auto-detected from TPM firmware version and the file:
      - Generation 1 (e.g. 1.771): Non-LMS format (321 byte manifest)
      - Generation 9 below 512: Non-LMS format (177 byte manifest)
      - Generation 9 at 512 and above: LMS format (2697 byte manifest)

# Run without arguments to display the current firmware information.
# This capture is an ST33TPHF2XSPI, which implements only the vendor codes.
./st33_fw_update
ST33 Firmware Update Tool
TPM2: Caps 0x30000415, Did 0x0000, Vid 0x104a, Rid 0x4e
TPM2_Startup pass
Mfg STM  (2), Vendor , Fw 1.258 (0x0)
Firmware version details: Major=1, Minor=258, Vendor=0x0
Part line: ST33TPHF2X (SPI firmware line)
Firmware generation: 1
Firmware update: Non-LMS format required (321 byte manifest)
Field upgrade command set:
	0x0000012f FieldUpgradeStart       (standard): not implemented
	0x00000141 FieldUpgradeData        (standard): not implemented
	0x2000030c FieldUpgradeStartVendor (ST33KTPM): implemented
	0x2000030d FieldUpgradeDataVendor  (ST33KTPM): implemented

# Run with firmware file (format auto-detected from TPM version)
./st33_fw_update TPM_ST33KTPM2X_00090200_V1.fi
ST33 Firmware Update Tool
	Firmware File: TPM_ST33KTPM2X_00090200_V1.fi
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.257 (0x0)
Firmware version details: Major=9, Minor=257, Vendor=0x0
Part line: ST33KTPM2X
Firmware generation: 9 below 512
Firmware update: Non-LMS format required (177 byte manifest)
	Format: Non-LMS (blob0 177 bytes, verified against the block chain)
Firmware Update:
	Total file size: 364290 bytes
	Manifest (blob0): 177 bytes
	Firmware data: 364113 bytes
	Image targets firmware: 9.512 (ST33KTPM2X)
	Command codes: start 0x2000030c, data 0x2000030d
...
Firmware update completed successfully.
Please reset or power cycle the TPM.
```

!!! note
    ファームウェアファイルは公開できないため、STMicroelectronics から別途入手する必要があります。

### LMS ファームウェア

512 以上のファームウェアを搭載した第 9 世代の TPM では、LMS 形式が必須です。

```sh
./st33_fw_update ST33KTPM2X_FAC_00090200_V2.fi
ST33 Firmware Update Tool
	Firmware File: ST33KTPM2X_FAC_00090200_V2.fi
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 3
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.512 (0x0)
Firmware version details: Major=9, Minor=512, Vendor=0x0
Firmware generation: 9 at 512 and above
Firmware update: LMS format required (2697 byte manifest)
	Format: LMS (blob0 2697 bytes, verified against the block chain)
Firmware Update:
	Total file size: 360092 bytes
	Manifest (blob0): 2697 bytes
	Firmware data: 357395 bytes
...
Firmware update completed successfully.
Please reset or power cycle the TPM.
```

### アップデートのキャンセル

```sh
./st33_fw_update --abandon
ST33 Firmware Update Tool
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.257 (0x0)
Firmware version details: Major=9, Minor=257, Vendor=0x0
Firmware generation: 9 below 512
Firmware update: Non-LMS format required (177 byte manifest)
Firmware Update Abandon:
Success: Please reset or power cycle TPM
```

同じツールはメインの README にも短いブロックで説明されています: `./examples/firmware/st33_fw_update` はファームウェア情報を表示し、`--abandon` は進行中のアップデートをキャンセルし、`<firmware.fi>` ファイルを渡すと、TPM のファームウェアバージョンから形式を自動検出してアップデートを実行します。

## ポリシーベースの認可 (上級)

デフォルトでは、wolfTPM はファームウェアアップデートの start コマンドに対するプラットフォーム階層の認可を内部で管理します。Infineon では、プラットフォームのプライマリポリシーに `PolicyCommandCode(TPM_CC_FieldUpgradeStartVendor)` ポリシーをインストールして満たします。ST33 では、空のプラットフォームパスワードによるパスワード認可 (`TPM_RS_PW`) を使用します。これは、プラットフォーム階層がデフォルト (空) の認可であることを前提としています。

ファームウェアアップグレードを独自のプラットフォームポリシー (例: 署名付きポリシーのチェック、PCR の状態、複数分岐の `PolicyOR`) で制御している環境では、`wolfTPM2_FirmwareUpgradeHash_ex()` を使用して、すでに満たされた認可セッションを渡すことができます。セッションを渡した場合の動作は次のとおりです。

- **Infineon**: ライブラリはプラットフォームのプライマリポリシーを上書きしません。プラットフォームの `authPolicy` は自分で (`authHandle = TPM_RH_PLATFORM` を指定した `TPM2_SetPrimaryPolicy` を通じて、SHA2-256 または SHA2-512 を使用して) プロビジョニングし、それを満たすセッションを渡します。これはライブラリに当てはまります。`--policy` と `--policyor` のサンプルモードは、それ自体がそのような呼び出し側であり、そのヘルパー (`examples/firmware/firmware_policy.c`) は、自ら生成したダイジェストでプラットフォームの `authPolicy` を上書きします。プラットフォーム階層に必要なポリシーがすでに設定されているシステムでは、これらのモードを実行しないでください。
- **ST33**: 渡されたセッションが、デフォルトの `TPM_RS_PW` パスワード認可を置き換えます。

サポートされるセッションの要件: ベンダーの `FieldUpgradeStart` コマンドは、セッションハンドルのみを含む認可領域とともに送信されます。このとき `nonceCaller` は空、セッション属性はゼロ、HMAC は空です。したがって、渡すセッションは、auth 値を持たず、パラメータ暗号化も行わない、ソルトなし・バインドなしの `TPM_SE_POLICY` セッションでなければなりません。`wolfTPM2_PolicyAuthValue()` や `wolfTPM2_PolicyPassword()` で満たすポリシーは、必要となるセッション HMAC がこの経路ではシリアライズされないため、サポートされません。そのようなセッションは、TPM に何かが送信される前に `BAD_FUNC_ARG` で拒否されます。`PolicyPCR`、`PolicySigned`、`PolicySecret`、`PolicyAuthorize`、`PolicyCommandCode`、`PolicyOR` の各分岐は使用できます。

セッションハッシュは `wolfTPM2_StartSession_ex(..., authHash)` で選択され、`wolfTPM2_PolicyOR()` は分岐ごとのダイジェストサイズを保持するため、SHA2-256 (非 PQC) と SHA2-512 (PQC) の両方のポリシーダイジェストがサポートされます。

例: 複数分岐の `PolicyOR` (最大 8 分岐、ここでは SHA2-512) を満たし、その下でアップグレードを開始します。

```c
WOLFTPM2_SESSION session;
TPML_DIGEST orList;
uint8_t manifest_hash[TPM_SHA512_DIGEST_SIZE];
int rc;

/* zero both structs: orList must not carry uninitialized branch sizes */
XMEMSET(&session, 0, sizeof(session));
XMEMSET(&orList, 0, sizeof(orList));

/* start a policy session using the desired policy hash (SHA2-512 for PQC) */
rc = wolfTPM2_StartSession_ex(&dev, &session, NULL, NULL,
    TPM_SE_POLICY, TPM_ALG_NULL, TPM_ALG_SHA512);
if (rc != TPM_RC_SUCCESS) goto cleanup;

/* Satisfy one branch (PCR, PolicySigned, PolicyAuthorize, PolicyCommandCode,
 * ...), then OR against the full branch list the platform authPolicy encodes.
 * Set count and each digests[i].size/buffer for every branch you populate.
 * PolicyOR requires at least 2 branches. */
orList.count = 2;
/* orList.digests[0].size = ...; XMEMCPY(orList.digests[0].buffer, ...); */
/* orList.digests[1].size = ...; XMEMCPY(orList.digests[1].buffer, ...); */
rc = wolfTPM2_PolicyOR(&dev, &session, &orList);
if (rc != TPM_RC_SUCCESS) goto cleanup;

/* hash the manifest with the matching algorithm, then start the upgrade under
 * the caller-satisfied session (NULL would use the library-default auth) */
rc = wc_Sha512Hash(manifest, manifest_sz, manifest_hash);
if (rc != 0) goto cleanup;
rc = wolfTPM2_FirmwareUpgradeHash_ex(&dev, TPM_ALG_SHA512,
    manifest_hash, (uint32_t)sizeof(manifest_hash),
    manifest, manifest_sz, fwDataCb, fwCbCtx, &session);

cleanup:
/* On a successful FieldUpgradeStart the TPM consumes the session and the
 * library sets session.handle.hndl to TPM_RH_NULL (0x40000007). It is NOT
 * zeroed, so do not test for == 0 to detect consumption. Calling
 * wolfTPM2_UnloadHandle is always safe: it is a no-op on TPM_RH_NULL, so this
 * only releases a session that is still loaded. */
if (session.handle.hndl != 0)
    wolfTPM2_UnloadHandle(&dev, &session.handle);
```

最後の `startSession` 引数に `NULL` を渡すと、`wolfTPM2_FirmwareUpgradeHash_ex()` は `wolfTPM2_FirmwareUpgradeHash()` (ライブラリが管理する認可) とまったく同じ動作になるため、既存のコードには影響しません。

### 破壊的: プロビジョニングは既存のプラットフォームポリシーを置き換える

!!! warning
    `--policy` と `--policyor` は、サンプルが生成したダイジェストを使って、プラットフォーム階層に対して `TPM2_SetPrimaryPolicy` を呼び出します。TPM 2.0 には、階層の `authPolicy` を読み戻す手段がありません。読み取りコマンドは存在せず、`TPMA_PERMANENT` が報告するのは `authValue` の状態のみです。そのため、サンプルは既存のポリシーを検出することも、保持することも、復元することもできません。クリーンアップは、以前に設定されていたものを復元するのではなく、ポリシーを削除します。

プラットフォーム階層が、保持する必要のあるポリシーで制御されている場合は、これらのモードを実行しないでください。サンプルはプロビジョニング時にこの警告を表示します。`--policytest` は影響を受けません。非破壊であり、`TPM2_SetPrimaryPolicy` を呼び出すことはありません。

これらのモードは、通常の動作モードも必要とします。リカバリモードとファイナライズモードでは、ライブラリは `FieldUpgradeStart` を完全にスキップするため、呼び出し側が用意したセッションは使用されません。サンプルは、何も使用しないポリシーをインストールするのではなく、実行を拒否します。ST33 では、TPM がすでにファームウェアアップグレードモードにある場合も、start コマンドがすでに実行済みであるため、同様にポリシーフラグは拒否されます。

### サンプルがプロビジョニングしたポリシーのロールバック

サンプルの `--policy` と `--policyor` モードは、アップグレードの前に `TPM2_SetPrimaryPolicy` でプラットフォーム階層の `authPolicy` をプロビジョニングします。失敗した場合、サンプルはそれを再びクリアするため、後続のデフォルト認可での実行がロックアウトされることはありません。成功した場合は、必要となる TPM リセットによってクリアされます。

- ロールバックは通常、プラットフォームのパスワード認可を使用します。TPM 2.0 Part 1 Sec. 19.7 によれば、階層は `authValue` または `authPolicy` のいずれかで認可されるため、`authPolicy` をインストールしてもパスワードの経路は無効になりません。デフォルトの空の `platformAuth` では、クリアは常に成功します。
- `--policyor` は、ファームウェア start の分岐とともに `PolicyCommandCode(TPM_CC_SetPrimaryPolicy)` の分岐もプロビジョニングするため、ポリシー自身がその削除を認可できます。パスワードの経路が失敗した場合 (非デフォルトの `platformAuth` を設定した環境)、サンプルはその分岐でクリアを再試行します。
- `--policy` は単一の `PolicyCommandCode(FieldUpgradeStart)` 分岐をプロビジョニングするため、ポリシーベースのロールバック経路はありません。`platformAuth` が引き続き使用できることに全面的に依存します。
- ロールバックは、サンプルが実際にポリシーをインストールした場合にのみ試行されます。したがって、早期の失敗 (たとえばファームウェアファイルが見つからない場合) によって、環境側がプロビジョニングしたポリシーがクリアされることはありません。
- ロールバックの失敗は明示的に報告され、終了ステータスになります。クリーンアップの前に実行が中断された場合、またはクリアに失敗した場合、TPM がリセットまたは電源を入れ直されるまで、プラットフォーム階層は引き続きそのポリシーを要求します。

## 関連項目

- [Supported hardware](supported-hardware.md)
- [Sealing and NVRAM](sealing-and-nvram.md)
- [TLS and certificates](tls-and-certificates.md)
- [Management and GPIO](management-and-gpio.md)
