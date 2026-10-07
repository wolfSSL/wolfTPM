# wolfTPM

組み込み用途向けに設計されたポータブルな TPM 2.0 プロジェクトです。このマニュアルでは、wolfTPM のビルド方法、お使いのハードウェア向けの設定方法、ネイティブ API とラッパー API の使い方、およびファームウェアTPM (fwTPM)、ポスト量子暗号、SPDM の各機能の実行方法を説明します。

## プロジェクトの機能

* この実装は、仕様に準拠したすべての TPM 2.0 API を提供します。
* 鍵の生成とロード、RSA 暗号化と復号、ECC 署名と検証、ECDH、NV、ハッシュ/HACM、AES、シーリングとアンシーリング、アテステーション、PCR Extend/Quote、Secure Root of Trust を簡単に扱うためのラッパーを提供します。
* TPM 2.0 に準拠した任意のモジュールをサポートします。動作確認済みのモジュールは、Infineon SLB9670、SLB9672、SLB9673、STMicroelectronics ST33KTPM2XSPI、ST33KTPM2I、ST33TPHF2XSPI、ST33TPHF2XI2C、Microchip ATTPM20、Nations Technologies/NSING Z32H330、NS350、Nuvoton NPCT650、NPCT750、SealSQ QVault TPM (シリコン上でポスト量子暗号 ML-DSA/ML-KEM を実装した初の TPM) です。
* wolfTPM は TPM Interface Specification (TIS) を使用して、SPI またはメモリマップド I/O 範囲経由で通信します。
* Linux では、wolfTPM は実行時にカーネルの TPM ドライバ (`/dev/tpmX`) と直接 SPI アクセスを自動検出して切り替えます。どちらのインターフェースでも、単純な `./configure && make` で動作します。
* wolfTPM は Linux の TPM カーネルインターフェース (`/dev/tpmX`) も利用でき、SPI、I2C、さらには LPC バス上の任意の物理 TPM と通信できます。
* Raspberry Pi (Linux)、MMIO、STM32 (CubeMX)、Atmel ASF、Xilinx、QNX、Infineon TriCore、wolfHAL、Barebox などのプラットフォームをサポートします。
* 設計上、さまざまなプラットフォームへ容易に移植できます。
    * 組み込み用途向けに設計されたネイティブ C コード。
    * ハードウェア SPI インターフェース用の単一の IO コールバック。
    * 外部依存なし。
    * コンパクトなコードサイズと最小限のメモリ使用量。
* 次のサンプルコードを含みます。
    * ほとんどの TPM2 ネイティブ API
    * すべての TPM2 ラッパー API
    * PKCS 7
    * 証明書署名要求 (CSR)
    * TLS クライアント
    * TLS サーバー
    * TPM の不揮発性メモリの利用
    * アテステーション (activate と make credential)
    * TPM アルゴリズムと TLS のベンチマーク
    * 鍵の生成 (プライマリ、RSA/ECC、対称鍵)、およびフラッシュ (NV メモリ) へのロードと保存
    * RSA 鍵または外部署名ポリシーによるデータのシーリングとアンシーリング。
    * 時刻の署名と設定
    * PCR の読み取りとリセット
    * GPIO の設定、読み取り、書き込み。
    * Endorsement Key/証明書の取得と検証。
* AES-CFB または XOR によるパラメータ暗号化をサポートします。
* salted unbound の認証セッションをサポートします。
* HMAC セッションをサポートします。
* Endorsement 証明書 (EK Credential Profile) の読み取りをサポートします。
* 個別の TPM チップを持たない組み込みプラットフォーム向けに、ポータブルな TPM 2.0 ファームウェア実装 (fwTPM。fTPM / swtpm とも呼ばれます) を含みます。[fwTPM の概要](fwtpm/overview.md)を参照してください。
* **ポスト量子暗号のサポート**: TPM 2.0 Library Specification v1.85 に基づき、ML-DSA (FIPS 204) 署名と ML-KEM (FIPS 203) 鍵カプセル化に対応します。`--enable-v185` (v1.85 全体) またはより軽量な `--enable-pqc` (ML-DSA / ML-KEM のみ) で有効にでき、`--enable-mldsa`/`--enable-mlkem` で操作ごとに絞り込めます。ML-DSA と ML-KEM を備えた wolfCrypt に対して `--enable-fwtpm` をビルドした場合は自動検出されます。クライアントライブラリと fwTPM サーバーの両方が、v1.85 で追加された 8 つの PQC コマンドを実装しています。[ポスト量子暗号](post-quantum.md)を参照してください。
* **SPDM アテステーションのサポート** (DMTF DSP0274): TCG の SPDM-over-TPM バインディング上で、TCG 証明書ハンドシェイクと DSP0274 事前共有鍵 (PSK) ハンドシェイクに対応し、`--enable-spdm` で有効になります。fwTPM サーバーには SPDM 1.3 レスポンダが含まれるため、ディスクリートなシリコンなしで CI 上でスタックをエンドツーエンドに検証できます。[SPDM アテステーション](spdm.md)を参照してください。

## 標準と機能

| 分野 | 状況 | 有効化フラグ | ページ |
| --- | --- | --- | --- |
| TPM 2.0 仕様 | すべての TPM 2.0 コマンドをネイティブ API に実装し、一般的な操作向けのラッパーを提供 | 常にビルドされる | [API リファレンス](api-reference.md) |
| TCG TPM 2.0 Library Specification v1.59 / v1.84 / v1.85 | v1.85 のポスト量子コマンドをクライアントライブラリと fwTPM サーバーに実装 | `--enable-v185` (v1.85 全体) | [ビルドオプション](build-options.md) |
| ポスト量子: ML-DSA (FIPS 204) と ML-KEM (FIPS 203) | クライアントライブラリと fwTPM サーバー。SealSQ QVault はシリコン上で対応 | `--enable-pqc` (ML-DSA / ML-KEM のみ)、`--enable-mldsa`、`--enable-mlkem` | [ポスト量子暗号](post-quantum.md) |
| SPDM アテステーション (TCG 証明書ハンドシェイクと DSP0274 PSK ハンドシェイク) | クライアントライブラリ、および fwTPM 内の SPDM 1.3 レスポンダ | `--enable-spdm` | [SPDM アテステーション](spdm.md) |
| パラメータ暗号化 (AES-CFB または XOR) | サポート。salted unbound セッションと HMAC セッションにも対応 | 実行時にセッションごとに設定 | [API リファレンス](api-reference.md) |
| EK Credential Profile | Endorsement 証明書の読み取り (`examples/endorsement/get_ek_certs`) | 常にビルドされる | [はじめに](getting-started.md) |
| デバイス ID (IAK / IDevID) | ST33KTPM で動作確認済み。デフォルトの鍵は NV 内の SHA2-384 を用いた ECDSA SECP384R1 | `WOLFTPM_MFG_IDENTITY` | [対応ハードウェア](supported-hardware.md) |
| ファームウェアTPM (fwTPM / fTPM / swtpm) | wolfCrypt 上に構築されたポータブルな TPM 2.0 サーバー | `--enable-fwtpm` | [fwTPM の概要](fwtpm/overview.md) |

## ドキュメントマップ

* [はじめに](getting-started.md): インストール後の最初の手順。
* [ビルド](building.md): ソースから wolfTPM をビルドします。
* [ビルドオプション](build-options.md): configure フラグと、それらが設定するマクロ定義。
* [対応ハードウェア](supported-hardware.md): 動作確認済みの TPM モジュールとプラットフォーム。
* [TPM 2.0 の概要](tpm2-overview.md): 階層、PCR、デバイス識別。
* [プロジェクト構成](project-structure.md): ソースツリーの構成。
* [ポスト量子暗号](post-quantum.md): ML-DSA と ML-KEM のサポート。
* [SPDM アテステーション](spdm.md): SPDM ハンドシェイクとレスポンダ。
* [fwTPM の概要](fwtpm/overview.md): ファームウェアTPM サーバー。
* [API リファレンス](api-reference.md): ネイティブ API とラッパー API。

## 関連項目

* [はじめに](getting-started.md)
* [ビルドオプション](build-options.md)
* [対応ハードウェア](supported-hardware.md)
* [fwTPM の概要](fwtpm/overview.md)
