# fwTPM の使用方法

このページでは、fwTPM サーバーの実行、クライアントの接続、トランスポートモード、NV の永続化、テスト、C API、および実際のボードでのサンプルについて説明します。先にサーバーをビルドするには、[ビルド](building.md)を参照してください。

## サーバーの起動

```sh
./src/fwtpm/fwtpm_server [options]
```

**オプション:**

| オプション | 説明 |
|--------|-------------|
| `--help`, `-h` | 使用方法を表示 |
| `--version`, `-v` | バージョン文字列を表示 |
| `--port <port>` | コマンドポート (デフォルト: 2321) |
| `--platform-port <port>` | プラットフォームポート (デフォルト: 2322) |
| `--clear` | NV をクリアした状態で起動 |
| `--spdm-tcg`, `--spdm-psk`, `--no-spdm` | SPDM レスポンダモード ([SPDM レスポンダ](spdm.md)を参照) |

`--port` と `--platform-port` オプションはソケットモード専用であり、TIS ビルド (`--enable-swtpm` なしの `--enable-fwtpm`) では使用できません。

**例:**

```sh
# Start with default ports (localhost:2321 command, :2322 platform)
./src/fwtpm/fwtpm_server

# Start on custom ports
./src/fwtpm/fwtpm_server --port 2331 --platform-port 2332

# Start with clear NV
./src/fwtpm/fwtpm_server --clear
```

サーバーは起動時に設定を出力します。

```
wolfTPM fwTPM Server v0.1.0
  Command port:  2321
  Platform port: 2322
  Manufacturer:  WOLF
  Model:         fwTPM
```

`--spdm-tcg` のテストモードでは、サーバーは生成したレスポンダの公開鍵も出力します。これはローカルのテストハーネス向けの便宜であり、ハードウェアレスポンダ向けのプロビジョニングやトラストアンカーのチャネルではありません。

## wolfTPM クライアントの接続

`--enable-swtpm` でビルドされた wolfTPM アプリケーションは、TCP 経由で fwTPM サーバーに自動的に接続します。組み込みの swtpm クライアントは mssim プロトコルを使用します。

```sh
# In one terminal: start the server
./src/fwtpm/fwtpm_server

# In another terminal: run wolfTPM examples
./examples/wrap/wrap_test
./examples/wrap/caps
./examples/keygen/keygen keyblob.bin -rsa -t
./examples/attestation/make_credential
```

### tpm2-tools の使用

ソケットモード (`--enable-swtpm`) では、サーバーは mssim (Microsoft TPM シミュレータ) と swtpm (Stefan Berger) の両方の TCTI プロトコルをサポートし、コマンドポート上で自動検出します。どちらの TCTI も使用できます。

```sh
# mssim TCTI (default for wolfTPM test scripts)
export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"
tpm2_startup -c

# swtpm TCTI (also works, auto-detected)
export TPM2TOOLS_TCTI="swtpm:host=localhost,port=2321"
tpm2_getrandom 8
```

## NV の永続化

サーバーは、永続的な状態 (階層シード、認可値、PCR の状態、NV インデックス) を `fwtpm_nv.bin` (`FWTPM_NV_FILE` で変更可能) に保存します。初回起動時にシードがランダムに生成されて保存され、以降の起動では既存の状態が再読み込みされます。

組み込みターゲットでは、ファイルバックエンドをフラッシュ、EEPROM、その他の NV HAL に置き換えます。ライトワンスフラッシュ向けのアペンドオンリーモードも含まれます。[HAL と移植](hal-and-porting.md)を参照してください。

## トランスポートモード

### ソケット / SWTPM (デフォルト)

`--enable-fwtpm --enable-swtpm` でビルドします。サーバーは SWTPM ワイヤプロトコルを使用して 2 つの TCP ポートで待ち受けます。

- **コマンドポート** (デフォルト 2321): TPM コマンドとレスポンスのトラフィック
- **プラットフォームポート** (デフォルト 2322): プラットフォームシグナル (電源オンとオフ、NV オン、キャンセル、リセット、セッション終了、停止)

**SWTPM TCP プロトコルのコマンド** (プラットフォームポート):

| シグナル | 値 | 説明 |
|--------|-------|-------------|
| `SIGNAL_POWER_ON` | 1 | TPM の電源をオン |
| `SIGNAL_POWER_OFF` | 2 | TPM の電源をオフ |
| `SIGNAL_PHYS_PRES_ON` | 3 | 物理プレゼンスをアサート |
| `SIGNAL_PHYS_PRES_OFF` | 4 | 物理プレゼンスをデアサート |
| `SIGNAL_HASH_START` | 5 | メジャードブートのハッシュを開始 |
| `SIGNAL_HASH_DATA` | 6 | メジャードブートのデータを提供 |
| `SIGNAL_HASH_END` | 9 | メジャードブートのハッシュを終了 |
| `SEND_COMMAND` | 8 | TPM コマンドを送信 (コマンドポート) |
| `SIGNAL_NV_ON` | 11 | NV ストレージが利用可能 |
| `SIGNAL_CANCEL_ON` | 13 | 現在のコマンドをキャンセル |
| `SIGNAL_CANCEL_OFF` | 14 | キャンセルを解除 |
| `SIGNAL_RESET` | 17 | TPM をリセット |
| `SESSION_END` | 20 | TCP セッションを終了 |
| `STOP` | 21 | サーバーを停止 |

wolfTPM クライアントは標準の SWTPM インターフェースを通じて接続します。これは `tpm2-tools` やその他の SWTPM 対応ソフトウェアと互換性があります。

### TIS / 共有メモリ

`--enable-fwtpm` (`--enable-swtpm` なし) でビルドします。このモードは、POSIX 共有メモリと名前付きセマフォを使用して、TIS (TPM Interface Specification) のレジスタレベルのアクセスをエミュレートします。SPI 接続の TPM をシミュレートします。

**共有メモリのレイアウト** (`FWTPM_TIS_SHM`):

| フィールド | 説明 |
|-------|-------------|
| `magic` / `version` | 検証用ヘッダー (`0x57544953` / "WTIS"、プロトコルバージョン 2) |
| `reg_addr`, `reg_len`, `reg_is_write`, `reg_data` | レジスタアクセス要求 |
| TIS レジスタシャドウ: `access`, `sts`, `int_enable`, `int_status`, `intf_caps`, `did_vid`, `rid` | エミュレートされた TIS レジスタ |
| `cmd_buf[4096]`, `cmd_len`, `fifo_write_pos` | コマンド FIFO |
| `rsp_buf[4096]`, `rsp_len`, `fifo_read_pos` | レスポンス FIFO |

**パス** (コンパイル時に設定可能):

| 定義 | デフォルト | 説明 |
|--------|---------|-------------|
| `FWTPM_TIS_SHM_PATH` | `/tmp/fwtpm.shm` | 共有メモリファイル。クライアントは、通常ファイル、単一リンク、同一 UID、サイズが完全一致する `0600` のエンドポイントを必要とします |
| `FWTPM_TIS_SEM_CMD` | `/fwtpm_cmd` | コマンドセマフォの名前 |
| `FWTPM_TIS_SEM_RSP` | `/fwtpm_rsp` | レスポンスセマフォの名前 |

クライアントは、プロトコルバージョンと共有領域サイズの完全一致を要求します。`FWTPM_TIS_FIFO_SIZE` に影響するオプションを変更する場合は、クライアントライブラリと `fwtpm_server` を併せて再ビルドしてください。デフォルトのパスはグローバルであるため、ホストごとに 1 つのサーバーを実行してください。

**サーバー側 API:**

- `FWTPM_TIS_Init()`: 共有メモリとセマフォを作成
- `FWTPM_TIS_Cleanup()`: 共有メモリとセマフォを削除
- `FWTPM_TIS_ServerLoop()`: TIS レジスタアクセスを処理し、コマンドをディスパッチ

**クライアント側 API** (`WOLFTPM_FWTPM_HAL` で有効化):

- `FWTPM_TIS_ClientConnect()`: 既存の共有メモリにアタッチ
- `FWTPM_TIS_ClientDisconnect()`: 共有メモリからデタッチ

## テスト

```sh
make check                  # Build + unit.test + run_examples.sh + tpm2-tools
scripts/tpm2_tools_test.sh  # tpm2-tools only (311 tests)
```

`make check` は `tests/fwtpm_check.sh` を実行し、これが `fwtpm_server` を自動的に起動および停止します。このためにサーバーを手動で起動しないでください。

### CI テスト (fwtpm-test.yml)

以下のテストはすべて GitHub Actions の CI で実行されます。PR を提出する前に手動で実行してください。ASan、UBSan、LeakSan のカバレッジは、このワークフローではなく `sanitizer.yml` にあります。

**ランタイムテスト (ビルド、run_examples.sh、make check):**

| 名前 | wolfTPM の設定 | 追加 | 備考 |
|------|---------------|-------|-------|
| fwtpm-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | 主要なテスト |
| fwtpm-tis | `--enable-fwtpm --enable-debug` | | TIS/SHM トランスポート |
| fwtpm-v185 | `--enable-fwtpm --enable-v185` | | PQC: ラッパーとハンドラーのユニットテスト |
| fwtpm-macos-socket | `--enable-fwtpm --enable-swtpm --enable-debug` | | macOS ランナー |

**ランタイムテスト、ゲートされたビルド (`fwtpm-gated-runtime` ジョブ):**

これらの構成はコマンドを削除するため、(サンプルと tpm2-tools を実行する) `make check` は適用できません。このジョブは `tests/fwtpm_unit.test` のみをビルドして実行します。`test_fwtpm_command_gates`、`test_fwtpm_total_commands`、`test_fwtpm_pcr_bounds` の各ケースは、ゲートされたコマンドが `TPM_RC_COMMAND_CODE` で拒否されること、`TPM_CAP_COMMANDS` に含まれないこと、`TPM_PT_TOTAL_COMMANDS` にカウントされないことを検証します。

| 名前 | wolfTPM の設定 | wolfSSL の設定 | 追加の CFLAGS |
|------|---------------|---------------|-------------|
| all-gates-ecc-only | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | 11 個のコマンドグループ `-DFWTPM_NO_*` ゲートをすべて併用 (NV は残す) |
| all-gates-mldsa | `--enable-fwtpm --enable-swtpm --enable-v185 --enable-mldsa` | `--enable-dilithium --enable-mlkem` | 同じ 11 個のゲート。ML-DSA では SequenceUpdate が残り、SequenceComplete が残らないことを検証 |
| reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |

**ビルドのみのテスト:**

| 名前 | wolfTPM の設定 | wolfSSL の設定 | 追加の CFLAGS |
|------|---------------|---------------|-------------|
| fwtpm-no-rsa | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | |
| fwtpm-no-ecc | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | |
| fwtpm-no-sha384 | `--enable-fwtpm --enable-swtpm` | `--disable-sha384` | |
| fwtpm-no-sha1 | `--enable-fwtpm --enable-swtpm` | `--disable-sha` | `-DNO_SHA` |
| fwtpm-v185-build-only | `--enable-fwtpm --enable-v185` | | `-DDEBUG_WOLFTPM` |
| fwtpm-only | `--enable-fwtpm-only --enable-swtpm` | | クライアントライブラリなし |
| fwtpm-minimal | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION -DFWTPM_NO_NV -DFWTPM_NO_POLICY -DFWTPM_NO_CREDENTIAL -DFWTPM_NO_DA -DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-policy | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_POLICY` |
| fwtpm-no-nv | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_NV` |
| fwtpm-no-attestation | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ATTESTATION` |
| fwtpm-no-credential | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CREDENTIAL` |
| fwtpm-no-da | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_DA` |
| fwtpm-no-param-enc | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_PARAM_ENC` |
| fwtpm-no-key-migration | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_KEY_MIGRATION` |
| fwtpm-no-ecdh | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_ECDH` |
| fwtpm-no-hash-cmds | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_HASH_CMDS` |
| fwtpm-no-context | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CONTEXT` |
| fwtpm-no-sym-encrypt | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_SYM_ENCRYPT` |
| fwtpm-no-clock | `--enable-fwtpm --enable-swtpm` | | `-DFWTPM_NO_CLOCK` |
| fwtpm-reduced-pcr | `--enable-fwtpm --enable-swtpm` | | `-DIMPLEMENTATION_PCR=8 -DPLATFORM_PCR=8` |
| fwtpm-no-rsa-no-policy | `--enable-fwtpm --enable-swtpm` | `--disable-rsa` | `-DFWTPM_NO_POLICY` |
| fwtpm-no-ecc-no-nv | `--enable-fwtpm --enable-swtpm` | `--disable-ecc` | `-DFWTPM_NO_NV` |
| fwtpm-small-stack | `--enable-fwtpm --enable-swtpm` | | `-DWOLFTPM_SMALL_STACK` |

**Pedantic ビルド (ビルドのみ、-Werror):**

| 名前 | コンパイラ | 設定 |
|------|----------|--------|
| fwtpm-pedantic-gcc | gcc | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-clang | clang | `--enable-fwtpm --enable-swtpm` |
| fwtpm-pedantic-only | gcc | `--enable-fwtpm-only` |

**別ジョブ: tpm2-tools (311 テスト):**

```sh
scripts/tpm2_tools_test.sh
```

## API リファレンス

### コア (`fwtpm.h`)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_Init(FWTPM_CTX* ctx)` | fwTPM コンテキストと RNG を初期化し、NV の状態をロード |
| `int FWTPM_Cleanup(FWTPM_CTX* ctx)` | NV を保存し、リソースを解放し、センシティブデータをゼロ化 |
| `const char* FWTPM_GetVersionString(void)` | バージョン文字列を返す (例: `"0.1.0"`) |

### コマンドプロセッサ (`fwtpm_command.h`)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_ProcessCommand(FWTPM_CTX* ctx, const byte* cmdBuf, int cmdSize, byte* rspBuf, int* rspSize, int locality)` | 生の TPM コマンドパケットを処理し、レスポンスを生成します。処理に成功した場合は `TPM_RC_SUCCESS` を返します。レスポンスバッファには TPM のエラー RC が含まれる場合があります。 |

### IO トランスポート (`fwtpm_io.h`)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_IO_SetHAL(FWTPM_CTX* ctx, FWTPM_IO_HAL* hal)` | カスタム IO トランスポートのコールバックを登録 |
| `int FWTPM_IO_Init(FWTPM_CTX* ctx)` | トランスポート (ソケットまたはカスタム HAL) を初期化 |
| `void FWTPM_IO_Cleanup(FWTPM_CTX* ctx)` | トランスポートを閉じ、リソースを解放 |
| `int FWTPM_IO_ServerLoop(FWTPM_CTX* ctx)` | メインのサーバーループ。`ctx->running` がクリアされるまでブロック |

### NV ストレージ (`fwtpm_nv.h`)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_NV_Init(FWTPM_CTX* ctx)` | ストレージから NV の状態をロード、または新規作成 (シードを生成) |
| `int FWTPM_NV_Save(FWTPM_CTX* ctx)` | 現在の TPM の状態を NV ストレージに保存 |
| `int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal)` | カスタム NV ストレージのコールバックを登録 |

### TIS サーバー (`fwtpm_tis.h`)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_TIS_Init(FWTPM_CTX* ctx)` | 共有メモリ領域とセマフォを作成 |
| `void FWTPM_TIS_Cleanup(FWTPM_CTX* ctx)` | 共有メモリとセマフォをアンリンク |
| `int FWTPM_TIS_ServerLoop(FWTPM_CTX* ctx)` | TIS レジスタアクセスを処理 (ブロック) |

### TIS クライアント (`fwtpm_tis.h`、`WOLFTPM_FWTPM_HAL` が必要)

| 関数 | 説明 |
|----------|-------------|
| `int FWTPM_TIS_ClientConnect(FWTPM_TIS_CLIENT_CTX* client)` | fwTPM の共有メモリにアタッチ |
| `void FWTPM_TIS_ClientDisconnect(FWTPM_TIS_CLIENT_CTX* client)` | 共有メモリからデタッチ |

## 実際のボードでのサンプル

[wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples) リポジトリには、実際のボード向けの完全な fwTPM プロジェクトが収められています。それぞれが、分離方式またはストレージ方式の異なる選択を示しています。

| ボード | プロジェクト | 示している内容 |
|-------|---------|----------------|
| STM32H5 NUCLEO-H563ZI | [STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) | Cortex-M33 TrustZone のセキュアワールド上の fwTPM、内蔵フラッシュの NV、mssim プロトコルを使用する UART |
| Xilinx ZCU102 (R5、ロックステップ) | [Xilinx/fwtpm-zcu102-r5](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zcu102-r5) | AMP: ロックステップの Cortex-R5 ペア上でベアメタル動作する fwTPM、A53 上の PetaLinux クライアントが OpenAMP RPMsg 経由で接続。揮発性の DDR NV または永続的な QSPI |
| Xilinx ZC702 (A9) | [Xilinx/fwtpm-zc702-a9](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zc702-a9) | SRAM-PUF から導出したデバイス固有の NV 鍵により、ルート鍵をフラッシュに保存しない |
| SCU35 (MicroBlaze-V ソフトコア) | [Xilinx/fwtpm-scu35-microblazev](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-scu35-microblazev) | 約 190 KB のブロック RAM に収まる ECC 専用の fwTPM |
| PolarFire SoC MPFS250T | [Microchip/fwtpm-polarfire-miv](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/fwtpm-polarfire-miv) | AMP: Linux から分離された U54 ハート上でベアメタル動作する fwTPM、共有 L2-LIM メモリ上の TIS |
| PolarFire MPF300 Splash (ソフト MIV) | [Microchip/miv-mpf300-splash](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/miv-mpf300-splash) | 永続的なオンダイ sNVM を備えたソフト Mi-V コア |

STM32H5、PolarFire SoC、ZCU102 のプロジェクトは、[HAL と移植](hal-and-porting.md)にも移植例として掲載されています。

## 関連項目

- [概要](overview.md)
- [ビルド](building.md)
- [HAL と移植](hal-and-porting.md)
- [ポスト量子サポート](post-quantum.md)
- [SPDM レスポンダ](spdm.md)
