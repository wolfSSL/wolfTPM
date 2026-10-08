# wolfTPM

組み込み用途向けに設計されたポータブルな TPM 2.0 プロジェクトです。このマニュアルでは、wolfTPM のビルド、ハードウェアに合わせた設定、ネイティブ API とラッパー API の使い方、ファームウェア TPM (fwTPM)、およびポスト量子暗号と SPDM 機能の実行方法を説明します。

## プロジェクトの特長

* 仕様に準拠したすべての TPM 2.0 API を提供します。
* 鍵の生成とロード、RSA 暗号化/復号、ECC 署名/検証、ECDH、NV、ハッシュ/HMAC、AES、シーリング/アンシーリング、アテステーション、PCR Extend/Quote、セキュアなルートオブトラストを簡単に扱うためのラッパーを提供します。
* TPM 2.0 に準拠したあらゆるモジュールに対応します。動作確認済みのモジュールは、Infineon SLB9670、SLB9672、SLB9673、STMicroelectronics ST33KTPM2XSPI、ST33KTPM2I、ST33TPHF2XSPI、ST33TPHF2XI2C、Microchip ATTPM20、Nations Technologies/NSING Z32H330、NS350、Nuvoton NPCT650、NPCT750、および SealSQ QVault TPM (シリコンとして初めてポスト量子の ML-DSA/ML-KEM に対応した TPM) です。
* wolfTPM は、TPM Interface Specification (TIS) を使用して、SPI またはメモリマップド I/O 領域経由で通信します。
* Linux では、wolfTPM は実行時にカーネルの TPM ドライバ (`/dev/tpmX`) と直接の SPI アクセスを自動検出します。`./configure && make` だけで、どちらのインターフェースでも動作します。
* wolfTPM は、Linux の TPM カーネルインターフェース (`/dev/tpmX`) を使って、SPI、I2C、さらには LPC バス上の物理 TPM とも通信できます。
* Raspberry Pi (Linux)、MMIO、CubeMX を使用する STM32、Atmel ASF、Xilinx、QNX、Infineon TriCore、wolfHAL、Barebox の各プラットフォームに対応します。
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
    * TPM の不揮発性メモリの使用
    * アテステーション (activate と make credential)
    * TPM アルゴリズムと TLS のベンチマーク
    * 鍵の生成 (プライマリ、RSA/ECC、対称鍵)、ロード、およびフラッシュ (NV メモリ) への保存
    * RSA 鍵または外部署名ポリシーによるデータのシーリングとアンシーリング
    * 署名付き時刻の取得と時刻の設定
    * PCR の読み取り/リセット
    * GPIO の設定、読み取り、書き込み
    * Endorsement Key/証明書の取得と検証
* AES-CFB または XOR を使用したパラメータ暗号化に対応します。
* ソルト付きの非バウンド認証セッションに対応します。
* HMAC セッションに対応します。
* Endorsement 証明書 (EK Credential Profile) の読み取りに対応します。
* 個別の TPM チップを持たない組み込みプラットフォーム向けに、ポータブルなファームウェア TPM 2.0 実装 (fwTPM。fTPM / swtpm とも呼ばれます) を含みます。[fwTPM の概要](fwtpm/overview.md)を参照してください。
* TPM 2.0 Library Specification v1.85 による**ポスト量子暗号のサポート**: ML-DSA (FIPS 204) 署名と ML-KEM (FIPS 203) 鍵カプセル化に対応し、`--enable-v185` (v1.85 全体) または、より軽量な `--enable-pqc` (ML-DSA / ML-KEM のみ) で有効にします。操作ごとの絞り込みは `--enable-mldsa`/`--enable-mlkem` で行えます。ML-DSA と ML-KEM を備えた wolfCrypt に対して `--enable-fwtpm` をビルドすると自動検出されます。クライアントライブラリと fwTPM サーバーの両方が、v1.85 で追加された 8 つの PQC コマンドを実装しています。[ポスト量子暗号](post-quantum.md)を参照してください。
* TCG SPDM-over-TPM バインディング上の **SPDM アテステーションのサポート** (DMTF DSP0274): TCG 証明書ハンドシェイクと DSP0274 の事前共有鍵 (PSK) ハンドシェイクに対応し、`--enable-spdm` で有効にします。fwTPM サーバーには SPDM 1.3 レスポンダが含まれているため、個別のシリコンなしでも CI でスタック全体をエンドツーエンドに検証できます。[SPDM アテステーション](spdm.md)を参照してください。

## 規格と機能

| 分野 | 状況 | 有効化フラグ | ページ |
| --- | --- | --- | --- |
| TPM 2.0 仕様 | TPM 2.0 コマンドセット用のネイティブ API と、一般的な操作用のラッパー | 常にビルドされます | [API リファレンス](api-reference.md) |
| TCG TPM 2.0 Library Specification リビジョン 1.85 | ポスト量子コマンドをクライアントライブラリと fwTPM サーバーに実装 | `--enable-v185` (v1.85 全体) | [ビルドオプション](build-options.md) |
| ポスト量子: ML-DSA (FIPS 204) と ML-KEM (FIPS 203) | クライアントライブラリと fwTPM サーバー。SealSQ QVault はシリコンで対応 | `--enable-pqc` (ML-DSA / ML-KEM のみ)、`--enable-mldsa`、`--enable-mlkem` | [ポスト量子暗号](post-quantum.md) |
| SPDM アテステーション (TCG 証明書ハンドシェイクと DSP0274 PSK ハンドシェイク) | クライアントライブラリ。fwTPM には SPDM 1.3 レスポンダも含まれます | `--enable-spdm` | [SPDM アテステーション](spdm.md) |
| パラメータ暗号化 (AES-CFB または XOR) | ソルト付き非バウンドセッションおよび HMAC セッションとあわせて対応 | 実行時にセッションごとに設定 | [API リファレンス](api-reference.md) |
| EK Credential Profile | Endorsement 証明書の読み取り (`examples/endorsement/get_ek_certs`) | 常にビルドされます | [はじめに](getting-started.md) |
| デバイス ID (IAK / IDevID) | ST33KTPM で検証済み。既定の鍵は、NV 内の SHA2-384 を用いた ECDSA SECP384R1 | `WOLFTPM_MFG_IDENTITY` | [対応ハードウェア](supported-hardware.md) |
| ファームウェア TPM (fwTPM / fTPM / swtpm) | wolfCrypt 上に構築されたポータブルな TPM 2.0 サーバー | `--enable-fwtpm` | [fwTPM の概要](fwtpm/overview.md) |

## ドキュメントマップ

* [はじめに](getting-started.md): インストール後の最初の手順。
* [ビルド](building.md): ソースからの wolfTPM のビルド。
* [ビルドオプション](build-options.md): configure フラグと、それらが設定する define。
* [対応ハードウェア](supported-hardware.md): 動作確認済みの TPM モジュールとプラットフォーム。
* [TPM 2.0 の概要](tpm2-overview.md): 階層、PCR、デバイス識別。
* [プロジェクト構成](project-structure.md): ソースツリーの構成。
* [ポスト量子暗号](post-quantum.md): ML-DSA と ML-KEM のサポート。
* [SPDM アテステーション](spdm.md): SPDM ハンドシェイクとレスポンダ。
* [fwTPM の概要](fwtpm/overview.md): ファームウェア TPM サーバー。
* [API リファレンス](api-reference.md): ネイティブ API とラッパー API。

## 関連項目

* [はじめに](getting-started.md)
* [ビルドオプション](build-options.md)
* [対応ハードウェア](supported-hardware.md)
* [fwTPM の概要](fwtpm/overview.md)
