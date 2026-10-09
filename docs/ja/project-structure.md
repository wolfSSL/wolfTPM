# プロジェクト構成

このページでは、wolfTPM ソースツリーのトップレベルディレクトリとそれぞれの目的を一覧にし、ファームウェアTPM と SPDM のサブディレクトリ、およびライブラリのヘッダについて補足します。

## ソースツリー

```
wolfTPM/
  src/            TPM 2.0 core library and wrappers
    fwtpm/        firmware TPM (fwTPM) server
    spdm/         SPDM responder and vendor adapters
  wolftpm/        public headers
    fwtpm/        fwTPM headers
    spdm/         SPDM headers
  examples/       example applications
  hal/            tpm_io_* IO callback backends
  tests/          unit and API tests
  IDE/            IDE and board projects
  docs/           this manual and the Doxyfile
  certs/          example keys and certificates
  cmake/          CMake support files
  m4/             autoconf macros
  scripts/        test and helper scripts
  tools/          documentation and SBOM tooling
  wrapper/        language wrappers
  zephyr/         Zephyr module
```

## ディレクトリの目的

| ディレクトリ | 目的 |
| --- | --- |
| `src/` | TPM 2.0 コア (`tpm2.c`、`tpm2_packet.c`、`tpm2_tis.c`、`tpm2_param_enc.c`、`tpm2_crypto.c`、`tpm2_asn.c`) とラッパー API (`tpm2_wrap.c`)。 |
| `src/fwtpm/` | ファームウェアTPM サーバー (`fwtpm_server`): コマンド処理、暗号、NV ストレージ、IO。 |
| `src/spdm/` | SPDM レスポンダとベンダーアダプタ。 |
| `wolftpm/` | `tpm2.h`、`tpm2_wrap.h`、`tpm2_types.h` を含む公開ヘッダ。 |
| `wolftpm/fwtpm/` | fwTPM サーバー用の公開ヘッダ。 |
| `wolftpm/spdm/` | SPDM 用の公開ヘッダ (`spdm.h`、`spdm_tcg.h`、`spdm_psk.h`、`spdm_responder.h`、およびベンダーヘッダ)。 |
| `examples/` | ネイティブ API とラッパー API のサンプルアプリケーション。 |
| `hal/` | Atmel、Barebox、Espressif、Infineon、Linux、Microchip、MMIO、QNX、ST、U-Boot、wolfHAL、Xilinx、Zephyr、fwTPM 向けの IO コールバックバックエンド (`tpm_io_*`)。 |
| `tests/` | ユニットテストと API テスト。 |
| `IDE/` | STM32CUBE、Espressif、QNX、IAR-EWARM、VisualStudio 向けのプロジェクト。 |
| `docs/` | このマニュアルと Doxygen 設定 (`Doxyfile`)。 |
| `certs/` | サンプルとテストで使用するサンプル鍵と証明書。 |
| `cmake/` | CMake サポートファイル。 |
| `m4/` | Autoconf マクロ。 |
| `scripts/` | テスト用およびヘルパースクリプト。 |
| `tools/` | ドキュメント用ツールと SBOM ジェネレータ (`tools/sbom`)。 |
| `wrapper/` | 言語ラッパー: `rust` と `CSharp`。 |
| `zephyr/` | Zephyr 統合。 |

## ライブラリの配置

wolfTPM のヘッダファイルは次の場所にあります。

| ライブラリ | ヘッダの場所 |
| --- | --- |
| wolfTPM | `wolftpm/` |
| wolfSSL | `wolfssl/` |
| wolfCrypt | `wolfssl/wolfcrypt` |

wolfTPM から include すべき汎用ヘッダを次に示します。

```c
#include <wolftpm/tpm2.h>
```

wolfTPM に付属するすべてのサンプルアプリケーションは、`hal/` にある `tpm_io.h` ヘッダを include します。`tpm_io.c` ファイルは、Linux カーネル、STM32 CubeMX HAL、または Atmel/Microchip ASF でサンプルアプリケーションをテストおよび実行するために必要な、サンプル用 HAL IO コールバックを設定します。このリファレンスは容易に変更でき、カスタムの IO コールバックや別のコールバックを必要に応じて追加または削除できます。

## 関連項目

* [ビルド](building.md)
* [ビルドオプション](build-options.md)
* [fwTPM の概要](fwtpm/overview.md)
* [SPDM アテステーション](spdm.md)
