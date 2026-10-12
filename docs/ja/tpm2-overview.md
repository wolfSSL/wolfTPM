# TPM 2.0 の概要

このページでは、TPM とは何か、wolfTPM が公開する階層と PCR、コード内で使われる用語、および通信している TPM モジュールの識別方法を説明します。

wolfTPM は、組み込み用途向けに設計された、API 後方互換性を備えたポータブルなオープンソースの TPM 2.0 スタックです。ネイティブ C で記述されていること、SPI ハードウェアインターフェース用の単一の IO コールバック、外部依存がないこと、コンパクトなコードと低いリソース使用量により、高い移植性を備えています。wolfTPM は、アテステーションのような複雑な TPM 操作を支援する API ラッパーと、TPM を使った証明書署名要求 (CSR) の生成のような複雑な暗号処理を支援するサンプルを提供します。

## プロトコルの概要

Trusted Platform Module (TPM。ISO/IEC 11889 とも呼ばれます) は、セキュア暗号プロセッサに関する国際標準であり、統合された暗号鍵によってハードウェアを保護するために設計された専用のマイクロコントローラです。各 TPM チップには製造時に一意で秘密の RSA 鍵が焼き込まれているため、コンピュータプログラムは TPM を使ってハードウェアデバイスを認証できます。

TPM は次の機能を提供します。

- 乱数生成器。
- 限定された用途向けの暗号鍵を安全に生成する機能。
- リモートアテステーション: ハードウェアとソフトウェア構成について、ほぼ偽造不可能なハッシュ鍵の要約を作成します。要約の範囲は、構成データをハッシュするソフトウェアによって決まります。これにより、第三者はソフトウェアが変更されていないことを検証できます。
- バインディング: ストレージ鍵から派生した一意の RSA 鍵である TPM バインド鍵を使ってデータを暗号化します。
- シーリング: バインディングに似ていますが、加えてデータを復号 (アンシール) できる TPM の状態を指定します。

TPM は、プラットフォームの完全性、ディスク暗号化、パスワード保護、ソフトウェアライセンス保護にも利用できます。

## 階層

```
Platform    TPM_RH_PLATFORM
Owner       TPM_RH_OWNER
Endorsement TPM_RH_ENDORSEMENT
```

各階層は、製造時に生成された独自のシードを持ちます。

`TPM2_Create` または `TPM2_CreatePrimary` で使用される引数がテンプレートを作成し、これが KDF に入力されて、使用した階層に基づく同じ鍵が生成されます。生成される鍵は、再起動後も毎回同じになります。新しい RSA 2048 ビット鍵の生成には約 15 秒かかります。通常、これらは作成後に `TPM2_EvictControl` を使って NV に保存されます。各 TPM は、シードに基づいて独自に一意の鍵を生成します。

エフェメラル階層 (`TPM_RH_NULL`) もあり、一時的な鍵の作成に使用できます。

## Platform Configuration Registers (PCR)

PCR は、TPM がサポートし割り当てたバンク内のインデックス 0 から 23 にハッシュダイジェストを保持します。PCR を extend することで、ブートシーケンスの完全性 (セキュアブート) を証明できます。

## 用語

このプロジェクトでは、append と marshall、parse と unmarshall という用語を使用します。

略語:

* HAL: Hardware Abstraction Layer (ハードウェア抽象化レイヤー)。
* NV: Non-Volatile memory (不揮発性メモリ)。
* TPM: Trusted Platform Module。

## デバイスの識別

次の行は、動作確認済みの各モジュールから取得した識別情報の出力です。`Caps/Did/Vid/Rid` の行は TIS バスレジスタから取得されます。

```
Infineon SLB9670:
TPM2: Caps 0x30000697, Did 0x001b, Vid 0x15d1, Rid 0x10
Mfg IFX (1), Vendor SLB9670, Fw 7.85 (4555), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9672:
TPM2: Caps 0x30000697, Did 0x001d, Vid 0x15d1, Rid 0x36
Mfg IFX (1), Vendor SLB9672, Fw 16.10 (0x4068), FIPS 140-2 1, CC-EAL4 1

Infineon SLB9673:
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a), FIPS 140-2 1, CC-EAL4 1

STMicro ST33KTPM2XSPI
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 0
Mfg STM  (2), Vendor ST33KTPM2XSPI, Fw 9.256 (0x0), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XSPI
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.8 (1151341959), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XSPI (newer firmware line)
TPM2: Caps 0x30000415, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 1.258 (0x0), FIPS 140-2 1, CC-EAL4 0

STMicro ST33TPHF2XI2C
TPM2: Caps 0x1a7e2882, Did 0x0000, Vid 0x104a, Rid 0x4e
Mfg STM  (2), Vendor , Fw 74.9 (1151341959), FIPS 140-2 1, CC-EAL4 0

Microchip ATTPM20
TPM2: Caps 0x30000695, Did 0x3205, Vid 0x1114, Rid 0x 1
Mfg MCHP (3), Vendor , Fw 512.20481 (0), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. Z32H330 TPM 2.0 module
Mfg NTZ (0), Vendor Z32H330, Fw 7.51 (419631892), FIPS 140-2 0, CC-EAL4 0

Nations Technologies Inc. NS350 TPM 2.0 module
TPM2: Caps 0x30000615, Did 0x0701, Vid 0x9999, Rid 0x 1
Mfg NSG (0), Vendor NS350, Fw 30.30 (0x24042510), FIPS 140-2 1, CC-EAL4 0

Nuvoton NPCT650 TPM2.0
Mfg NTC (0), Vendor rlsNPCT , Fw 1.3 (65536), FIPS 140-2 0, CC-EAL4 0

Nuvoton NPCT750 TPM2.0
TPM2: Caps 0x30000697, Did 0x00fc, Vid 0x1050, Rid 0x 1
Mfg NTC (0), Vendor NPCT75x"!!4rls, Fw 7.2 (131072), FIPS 140-2 1, CC-EAL4 0

SealSQ QVault TPM 2.0
TPM2: Caps 0x30000797, Did 0x0083, Vid 0x2406, Rid 0x 3
Mfg SEAL (6), Vendor QVault TPM, Fw 2.1 (0x3010303), FIPS 140-3, CC-EAL4 0

NVIDIA Jetson Orin (Tegra234) OP-TEE firmware TPM, via /dev/tpmrm0
Mfg MSFT (7), Vendor SSE fTPM, Fw 8216.1808 (0x105300), FIPS 140-2, CC-EAL4 0
```

ST33TPHF2X の初期の 1.x ファームウェアは、`TPM_PT_VENDOR_STRING_1..4` をテキストではなくバイナリとして報告するため、`Vendor` フィールドは空で表示されます。後期の 1.x ファームウェアは `ST33TPHF2XSPI` のような ASCII を報告します。代わりにファームウェアのメジャーバージョンでラインを識別できます。1.x と 2.x は ST33TPHF2X (それぞれ SPI ファームウェアと I2C ファームウェア)、9.x は ST33KTPM2X、10.x は ST33KTPM2A です。これがファームウェア更新フォーマットとコマンドコードの選択にどう使われるかは、wolfTPM ソースツリーの `examples/firmware/README.md` を参照してください。

!!! note
    NVIDIA Jetson Orin のエントリに `Caps/Did/Vid/Rid` の行がないのは、これらの値が TIS バスレジスタから取得されるものであり、ファームウェアTPM にはそれがないためです。このエントリは `--enable-autodetect` で取得したもので、この場合 `wolfTPM2_Init_ex` はカーネルデバイスが開いた時点で戻るため、デバッグ行には到達しません。`--enable-devtpm` ビルドでは引き続きこの行が出力されますが、すべて 0 が読み取られます。`Fw 8216.1808` は `TPM_PT_FIRMWARE_VERSION_1` = `0x20180710` であり、この実装ではバージョン番号ではなくビルド日 (2018-07-10) を表すために使われています。仕様リビジョンは 1.62 で、4 つの PCR バンク (SHA-1、SHA-256、SHA-384、SHA-512) がすべて PCR 0 から 23 で割り当てられています。

## 関連項目

* [対応ハードウェア](supported-hardware.md)
* [API リファレンス](api-reference.md)
* [はじめに](getting-started.md)
* [プロジェクト構成](project-structure.md)
