# ビルドオプション

このページは、wolfTPM のビルド方法を制御する Autotools (`./configure`) オプションとプリプロセッサ定義のリファレンスです。各 configure スイッチには、対応するマクロがある場合はそのマクロを記載しています。正式な情報源は wolfTPM ソースツリーの `configure.ac` です。

!!! note
    このページでは Autotools ビルドについて説明します。CMake ビルドは異なります。fwTPM はデフォルトで無効であり、TPM インターフェースは `--enable-*` フラグではなく `WOLFTPM_INTERFACE` キャッシュ変数 (`auto`、`SWTPM`、`WINAPI`、`DEVTPM`、`SPI`、`I2C`、`MMIO`) で選択します。CMake については [Building wolfTPM](building.md) を参照してください。

## 表の読み方

- すべての `--enable-X` フラグには `--disable-X` 形式もあります。デフォルト列は、フラグを指定しなかった場合の状態を示します。
- 一部のマクロはオプトアウト型です。`WOLFTPM2_NO_WRAPPER` は `--disable-wrapper` で定義され、`WOLFTPM2_NO_WOLFCRYPT` は `--disable-wolfcrypt` で定義されます。enable 形式ではこれらは定義されません。
- 生成される `wolftpm/options.h` には、configure 時に選択されたマクロが記録されます。

## 一般およびデバッグ

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-debug[=yes\|no\|verbose\|io]` | no | デバッグコードを追加し、最適化を無効にします。`DEBUG_WOLFTPM` を定義します。`verbose` は `WOLFTPM_DEBUG_VERBOSE` も定義し、`io` は `WOLFTPM_DEBUG_VERBOSE` と `WOLFTPM_DEBUG_IO` の両方を定義します。 |
| `--enable-examples` | enabled | サンプルプログラムをビルドします。 |
| `--enable-wrapper` | enabled | ラッパー API をビルドします。`--disable-wrapper` は `WOLFTPM2_NO_WRAPPER` を定義します。 |
| `--enable-wolfcrypt` | enabled | RNG、認可セッション、パラメータ暗号化に wolfCrypt を使用します。`--disable-wolfcrypt` は `WOLFTPM2_NO_WOLFCRYPT` を定義します。 |
| `--with-wolfcrypt=PATH` | `/usr/local` | wolfSSL のインストール先のパスです。このディレクトリには `lib` と `include` が含まれている必要があります。 |
| `--enable-smallstack` | disabled | スタック使用量を削減するために `WOLFTPM_SMALL_STACK` を定義します。あわせて `MAX_COMMAND_SIZE=1024`、`MAX_RESPONSE_SIZE=1350`、`MAX_DIGEST_BUFFER=896` を設定します。`--disable-wolfcrypt` と併用すると、`MAX_SESSION_NUM=1` も設定します。 |
| `--enable-provisioning` | enabled | Initial Device Identity (IDevID) と Attestation Identity Key のプロビジョニングをサポートします。`WOLFTPM_PROVISIONING` を定義します。 |
| `--enable-firmware` | enabled | Infineon SLB9672/SLB9673 および ST ST33 の TPM ファームウェアアップグレードをサポートします。`WOLFTPM_FIRMWARE_UPGRADE` を定義します。無効にするには `--disable-firmware` を使用します。 |
| `--enable-fuzz` | disabled | ファズターゲットをビルドします。 |

!!! warning
    `WOLFTPM_DEBUG_SECRETS` はどの configure オプションでも設定されず、デフォルトでは無効です。手動で定義すると、認可値、セッションキー、バインドキー、HMAC キー、階層の認可値、暗号化シークレットなどの機密情報が出力されます。開発者のデバッグ用途に限って使用してください。本番ビルドや、標準出力を永続ストレージに記録するデバイスでは、決して有効にしないでください。

## I/O レイヤーとバス選択

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-spi` | not set | SPI ハードウェアビルドの意図を示すシグナルです。`--enable-i2c` が指定されていない場合、SPI がデフォルトのトランスポートになります。マクロは追加しませんが、ハードウェア選択として扱われるため、swTPM と fwTPM の自動デフォルトが無効になります。`--enable-i2c` と併用することはできません。 |
| `--enable-i2c` | disabled | I2C TPM をサポートします。`WOLFTPM_I2C` を定義し、`WOLFTPM_ADV_IO` を自動的に定義します。 |
| `--enable-mmio` | disabled | 組み込みのメモリマップド I/O コールバックを使用します。`WOLFTPM_MMIO` を定義し、`WOLFTPM_ADV_IO` を自動的に定義します。 |
| `--enable-advio` | disabled | 拡張 I/O コールバックのシグネチャを使用します。`WOLFTPM_ADV_IO` を定義します。I2C または MMIO と併用する場合は、別途指定する必要はありません。 |
| `--enable-wolfhal` | disabled | wolfHAL の I/O コールバックを使用します。`WOLFTPM_WOLFHAL` を定義します。wolfHAL のヘッダーと、アプリケーションが提供する `board.h` が必要です。必要な `BOARD_*` 定義については `hal/README.md` を参照してください。 |
| `--enable-hal` | enabled | サンプルの HAL インターフェースをビルドします。`WOLFTPM_EXAMPLE_HAL` を定義します。 |
| `--enable-hal-reset[=LINE]` | disabled | Linux GPIO キャラクタデバイス経由の TPM nRST リセット HAL です。常に `WOLFTPM_HAL_RESET` を定義します。数値の `LINE` を指定すると `WOLFTPM_RESET_LINE` も定義します。ライン未指定の場合のデフォルトは、ST33 では GPIO24、Nuvoton では GPIO4 です。`TPM2_IoCb_Reset()` で駆動します。 |
| `--enable-checkwaitstate` | depends on chip | TIS および SPI のウェイトステート確認をサポートします。`WOLFTPM_CHECK_WAIT_STATE` を定義します。configure は、autodetect の場合と、Infineon 専用ではないすべてのビルドで有効にします。 |
| `--enable-tislock` | disabled | `WOLFTPM_TIS_LOCK` を定義します。名前付きセマフォを使用して、プロセス間で TIS コマンドをシリアライズします。Linux のみ対応です。 |

`--enable-hal-reset` には SPI または I2C のハードウェア HAL が必要です。configure は、swTPM または `--enable-devtpm` との併用を拒否します。一般的なホストでは swTPM がデフォルトであるため、併用する場合は `--enable-spi` または `--enable-i2c` を指定してください。

!!! note
    Raspberry Pi で I2C を使用するには、あらかじめ I2C を有効にする必要がある場合があります。

    1. 現在の Raspberry Pi OS では `/boot/firmware/config.txt` を編集します (例: `sudo vim /boot/firmware/config.txt`)。古いイメージでは `/boot/config.txt` を使用します。
    2. `dtparam=i2c_arm=on` のコメントを解除します。
    3. `sudo reboot` で再起動します。

## TPM ベンダーとモジュール

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-infineon[=slb9670\|slb9672\|slb9673]` | disabled | 引数なしの `--enable-infineon` は SLB9672 を選択し、`WOLFTPM_SLB9672` を定義します。`--enable-infineon=slb9670` は `WOLFTPM_SLB9670` を定義します。`--enable-infineon=slb9673` は `WOLFTPM_SLB9673` を定義し、I2C 専用です。`--enable-i2c` を使用し、`--enable-spi` は指定しないでください。 |
| `--enable-st33`, `--enable-st` | disabled | ST ST33 をサポートします。`WOLFTPM_ST33` を定義します。2 つのフラグは同等です。 |
| `--enable-microchip`, `--enable-mchp` | disabled | Microchip ATTPM20 をサポートします。`WOLFTPM_MICROCHIP` を定義します。2 つのフラグは同等です。 |
| `--enable-nuvoton` | disabled | Nuvoton NPCT65x/NPCT75x をサポートします。`WOLFTPM_NUVOTON` を定義します。 |
| `--enable-nations` | disabled | Nations Technology NS350 をサポートします。`WOLFTPM_NATIONS` を定義します。 |
| `--enable-sealsq` | disabled | SealSQ QVault のポスト量子 TPM をサポートします。`WOLFTPM_SEALSQ` を定義します。 |
| `--enable-autodetect` | on when no vendor module is selected | 実行時にモジュールを検出します。`WOLFTPM_AUTODETECT` を定義します。 |

引数を指定して Infineon デバイスを選択する例を示します。

```sh
./configure --enable-infineon=slb9670
./configure --enable-infineon=slb9673 --enable-i2c
```

## オペレーティングシステムのトランスポートとシミュレータ

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-devtpm` | disabled | Linux カーネルドライバー (`/dev/tpmrm0` または `/dev/tpm0`) を使用します。`WOLFTPM_LINUX_DEV` を定義します。swTPM と併用することはできません。 |
| `--enable-swtpm` | see below | swtpm の TCP プロトコルでシミュレータと通信します。`WOLFTPM_SWTPM` と `TPM2_SWTPM_PORT` を定義します。 |
| `--enable-swtpm=uart` | disabled | UART シリアルポート上の swtpm プロトコルです。STM32H5 などの組み込みターゲットでの fwTPM 向けです。`WOLFTPM_SWTPM`、`WOLFTPM_SWTPM_UART`、`TPM2_SWTPM_PORT` を定義し、ポート値はボーレート (デフォルト 115200) になります。 |
| `--with-swtpm-port=PORT` | 2321 | `TPM2_SWTPM_PORT` を設定します。`--enable-swtpm=uart` の場合は、代わりにボーレートを設定します。 |
| `--enable-fwtpm` | see below | ファームウェア TPM (fwTPM) サーバーをビルドします。wolfCrypt が必要です。 |
| `--enable-winapi` (alias `--enable-wintbs`) | disabled | Windows TBS API を使用します。`WOLFTPM_WINAPI` を定義します。swTPM または devtpm と併用することはできません。 |

### シミュレータのデフォルト動作

`--enable-swtpm` と `--enable-fwtpm` は、次のすべてが成り立つ場合にデフォルトで有効になります。

- ホスト CPU が x86_64、amd64、または aarch64 である。
- ホスト OS が Windows (mingw、cygwin、msys、win32) ではない。
- wolfCrypt が有効である。
- `--enable-spi`、`--enable-i2c`、`--enable-mmio`、`--enable-devtpm`、`--enable-autodetect`、`--enable-winapi`、`--enable-infineon`、`--enable-st`、`--enable-st33`、`--enable-microchip`、`--enable-nuvoton`、`--enable-nations`、`--enable-sealsq` のいずれでもハードウェアパスが選択されていない。

これは Linux だけでなく macOS と BSD にも当てはまります。それ以外の環境では、デフォルトは無効です。

!!! warning
    これらのホストでオプションなしの `./configure` を実行すると、`WOLFTPM_AUTODETECT` と `WOLFTPM_SWTPM` の両方が定義される場合があります。`WOLFTPM_SWTPM` はカーネルデバイスの検出を抑止するため、そのようなビルドは `/dev/tpmrm0` や `/dev/tpm0` を試行しません。実際の TPM を使用するには、`--enable-autodetect`、`--enable-devtpm`、またはベンダーフラグを明示的に指定してください。`--enable-autodetect` を明示するとシミュレータのデフォルトが無効になり、カーネル優先の動作になります。Linux では実行時に `/dev/tpmrm0` または `/dev/tpm0` を試行し、カーネルドライバーが利用できない場合は SPI にフォールバックします。

### fwTPM のマクロ

| Macro | Where it is set |
| --- | --- |
| `WOLFTPM_FWTPM_BUILD` | あらゆる fwTPM ビルドで、生成される `options.h` に追加されます。テストスクリプトが参照するマーカーです。 |
| `WOLFTPM_FWTPM` | fwTPM サーバーとファズターゲットにのみ設定されます。共有ソース内のサーバー側コードを制御します。 |
| `WOLFTPM_FWTPM_HAL`, `WOLFTPM_ADV_IO` | TIS および共有メモリのビルド、つまり `--enable-swtpm` を伴わない fwTPM で追加されます。Windows ではサポートされません。 |

### fwTPM 専用モードと NV モード

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-fwtpm-only` | disabled | fwTPM サーバーのみをビルドします。クライアントライブラリ、ラッパー、サンプルをスキップし、`WOLFTPM2_NO_WRAPPER` を定義します。`--enable-fwtpm` を暗黙的に有効にし、wolfCrypt が必要です。`--enable-spdm` とは互換性がありません。 |
| `--enable-fwtpm-nv-appendonly` | disabled | 書き込み一回限りのフラッシュ向け fwTPM ポートのための、追記専用 NV ジャーナルモードです。`WOLFTPM_FWTPM_NV_APPEND_ONLY` を定義します。 |

## SPDM

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-spdm` | disabled | SPDM をサポートします。`WOLFTPM_SPDM` を定義します。wolfSPDM サブモジュールが必要です。`git submodule update --init lib/wolfSPDM` を実行してください。fwTPM と併用すると `WOLFTPM_SPDM_RESPONDER` も定義します。 |
| `--enable-tcg` | auto under `--enable-spdm` | SPDM TCG バインディングモードです。`WOLFTPM_SPDM_TCG` を定義します。fwTPM、Nuvoton、Nations では自動的に有効になります。 |
| `--enable-psk` | auto with Nations | SPDM PSK モードです。`WOLFTPM_SPDM_PSK` を定義します。`--enable-tcg` が必要です。 |

configure が強制する関連ルールは次のとおりです。

- `--enable-tcg` と `--enable-psk` には `--enable-spdm` が必要です。
- SPDM を伴う `--enable-nuvoton` には `--enable-tcg` が必要で、`WOLFSPDM_NUVOTON` を定義します。
- SPDM を伴う `--enable-nations` には `--enable-tcg` と `--enable-psk` の両方が必要で、`WOLFSPDM_NATIONS` を定義します。
- SPDM を伴う fwTPM には、`--enable-tcg` または `--enable-psk` の少なくとも一方が必要です。
- `--with-wolfspdm` は廃止されており、指定すると configure が失敗します。`--enable-spdm` を使用してください。
- SPDM を伴うデバッグビルドは `WOLFSPDM_DEBUG` も定義します。

## ポスト量子 (v1.85)

| Option | Default | Effect and macros |
| --- | --- | --- |
| `--enable-v185` | auto-detect | TPM 2.0 v1.85 の全機能を有効にします。ML-DSA と ML-KEM、署名および検証のシーケンスコマンドとダイジェストコマンド、新しいレスポンスコード、新しいケイパビリティプロパティが含まれます。`WOLFTPM_V185` を定義します。wolfCrypt が ML-DSA と ML-KEM の両方を備えている場合、fwTPM ビルドでは自動的に有効になります。 |
| `--enable-pqc` | auto-detect | ポスト量子の軽量サブセット (ML-DSA と ML-KEM のみ) です。`WOLFTPM_PQC` を定義します。fwTPM ビルドでは完全な v1.85 に昇格します。両方を指定した場合は `--enable-v185` が優先されます。 |
| `--enable-mldsa[=all\|sign-only\|verify-only\|no]` | all | ML-DSA を制限します。`sign-only` は `WOLFTPM_NO_MLDSA_VERIFY` を、`verify-only` は `WOLFTPM_NO_MLDSA_SIGN` を、`no` は `WOLFTPM_NO_MLDSA` を定義します。 |
| `--enable-mlkem[=all\|enc\|dec\|no]` | all | ML-KEM を制限します。`enc` は `WOLFTPM_NO_MLKEM_DECAP` を、`dec` は `WOLFTPM_NO_MLKEM_ENCAP` を、`no` は `WOLFTPM_NO_MLKEM` を定義します。 |
| `--disable-hash-mldsa` | pre-hash enabled | プリハッシュ ML-DSA キーのサポートを除外します。`WOLFTPM_NO_HASH_MLDSA` を定義します。 |

自動検出を含め、ポスト量子サポートを無効にするには `--disable-v185` または `--disable-pqc` を使用します。`--enable-mldsa=no` と `--enable-mlkem=no` の両方を指定するとエラーになります。wolfCrypt が有効な場合、PQC には ML-DSA (`--enable-mldsa`、または wolfSSL のエイリアス `--enable-dilithium`) と ML-KEM (`--enable-mlkem`) を有効にしてビルドした wolfSSL 5.9.2-stable 以降が必要です。`--disable-wolfcrypt` の場合、PQC はコマンドのマーシャリングのみとなります。

## プリプロセッサ定義

これらは configure オプションではありません。`CFLAGS` で設定します。例: `./configure CFLAGS="-DWOLFTPM_MAX_RETRIES=3"`。

| Macro | Effect |
| --- | --- |
| `WOLFTPM_USE_SYMMETRIC` | TLS サンプル向けに、対称 AES、ハッシュ、HMAC のサポートを有効にします。 |
| `WOLFTPM2_USE_SW_ECDHE` | TLS サンプルが ECC 一時鍵の生成と共有シークレットの導出に TPM を使用しないようにします。 |
| `TLS_BENCH_MODE` | TLS ベンチマークモードを有効にします。 |
| `NO_TPM_BENCH` | TPM ベンチマークサンプルを無効にします。 |
| `WOLFTPM2_ECC_DEFAULT_CURVE` | 曲線を明示しない名前付きラッパーテンプレート (現在は SRK と AIK) が使用する曲線です。デフォルトは `TPM_ECC_NIST_P256`、または `ECC_MIN_KEY_SZ` を満たす有効な最小の曲線です。`-DWOLFTPM2_ECC_DEFAULT_CURVE=TPM_ECC_NIST_P384` のように上書きできます。`wolfTPM2_GetKeyTemplate_ECC` と `_ECC_ex` は曲線を明示的に受け取るため、このマクロによる置き換えは行われません。ただし `NO_ECC256` が設定されている場合は P-256 が代替されます。 |
| `WOLFTPM_MAX_RETRIES` | TPM が `TPM_RC_RETRY` を返した場合 (TPM が一時的にビジー状態の場合。たとえば、`noDA` なしで外部からプロビジョニングされたキーを初めて認可に使用する際に `daUsed` フラグを永続化している間など) に、コマンドを再送信するデフォルトの回数です。デフォルトは 0 で、無効です。実行時に `TPM2_SetCommandRetries()` で、またはビルド時に `-DWOLFTPM_MAX_RETRIES=N` で有効にできます。wolfTPM は作成するすべてのキーに `noDA` を設定するわけではありません。汎用のキーテンプレート API は呼び出し側が渡した属性を使用し、EK テンプレートは `noDA` を省略するため、これらのキーではこの状態が発生し得ます。 |
| `WOLFTPM_NO_RETRY` | `TPM_RC_RETRY` の再送信処理をコンパイルから除外します。`TPM_RC_RETRY` は呼び出し側に返されます。0 より大きい `WOLFTPM_MAX_RETRIES` とは競合します。 |
| `WOLFTPM_LOCALITY_DEFAULT` | 起動時に要求される TIS ロケーリティです (デフォルトは 0)。SPI、メモリマップド、swtpm のトランスポートでは、実行時に `wolfTPM2_SetLocality()` で変更できます。wolfTPM の I2C HAL はロケーリティ選択を実装しておらず、ロケーリティ 0 のみを使用するため、I2C で 0 以外を指定して `wolfTPM2_SetLocality()` を呼び出すと `NOT_COMPILED_IN` が返されます。 |
| `WOLFTPM_TIS_RESET_STALE_LOCALITY` | 起動時に、`WOLFTPM_LOCALITY_DEFAULT` 以外でアクティブなロケーリティを解放し、デフォルトを付与できるようにします。前回のセッションがロケーリティを解放しなかったために停止状態になった TPM を復旧します。デフォルトでは無効です。共有バスでは別のマスターが保持しているロケーリティを解除してしまう可能性があるため、シングルマスターバスでのみ使用してください。代替手段として nRST リセット HAL があります。 |
| `WOLFTPM_LOCALITY_TIMEOUT_TRIES` | 実行時にロケーリティを要求する際のポーリング試行回数です (デフォルトは 1000)。付与できないロケーリティを素早く失敗させるため、小さい値になっています。 |
| `WOLFTPM_RESET_LINE` | リセット HAL 用の nRST GPIO ライン番号です。`--enable-hal-reset=LINE` で設定します。 |

## 関連項目

- [wolfTPM のビルド](building.md)
- [システムインターフェース](system-interfaces.md)
- [サポート対象ハードウェア](supported-hardware.md)
- [はじめに](getting-started.md)
