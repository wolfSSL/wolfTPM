# サポート対象ハードウェア

wolfTPM は、単一の HAL I/O コールバックを通じて SPI または I2C 経由で TPM 2.0 パーツと通信するか、オペレーティングシステムのドライバー経由でシステム TPM と通信します。このページでは、wolfTPM が HAL バックエンドを備えているプラットフォーム、テスト済みのハードウェア、各パーツに対応する configure フラグ、ベンダーごとのビルド手順を示します。

## プラットフォーム

ハードウェアのサンプルは、Linux の `spidev` インターフェースを使用して Raspberry Pi 上で実行されることが最も多くなっています。これはサンプルのプラットフォームであり、必須条件ではありません。Linux HAL はベンダーごとにデフォルトの SPI チップセレクトを選択します。Infineon のビルドは `/dev/spidev0.1` を使用し、Microchip、ST、Nuvoton、Nations Technologies、SEALSQ のビルドは `/dev/spidev0.0` を使用します。配線が異なる場合は、`TPM2_SPI_DEV_PATH` と `TPM2_SPI_DEV_CS` でデバイスを上書きしてください。

ハードウェアバス (SPI または I2C) とのインターフェースには、wolfTPM は単一の HAL コールバックを使用します。このコールバックは、`TPM2_Init` または `wolfTPM2_Init` の呼び出し時の初期化中に渡します。コールバックモデルについては [HAL IO Callback](hal-io-callback.md) を参照してください。

`hal` ディレクトリには、次の HAL 実装例が用意されています。

* Atmel ASF (`tpm_io_atmel.c`)
* Barebox (`tpm_io_barebox.c`)
* Espressif ESP-IDF (`tpm_io_espressif.c`)
* Firmware TPM (`tpm_io_fwtpm.c`)
* Infineon TriCore and PSoC/CyHAL (`tpm_io_infineon.c`)
* Linux SPI and I2C (`tpm_io_linux.c`)
* Memory-mapped I/O (`tpm_io_mmio.c`)
* Microchip Harmony (`tpm_io_microchip.c`)
* QNX (`tpm_io_qnx.c`)
* STM32 CubeMX (`tpm_io_st.c`)
* U-Boot (`tpm_io_uboot.c`)
* wolfHAL (`tpm_io_wolfhal.c`)
* Xilinx (`tpm_io_xilinx.c`)
* Zephyr (`tpm_io_zephyr.c`)

拡張 I/O オプション (`--enable-advio` または `WOLFTPM_ADV_IO`) は、レジスタアドレスと読み書きフラグを I/O コールバックのパラメータとして追加します。これは I2C サポートに必須であり、`--enable-i2c` を指定すると有効になります。

## テスト済みハードウェア

wolfTPM は次のハードウェアでテストされています。

* Infineon OPTIGA(TM) Trusted Platform Module 2.0 SLB9670 (SPI)、SLB9672 (SPI)、SLB9673 (I2C)。
    * [LetsTrust](https://letstrust.de) は TPM 開発ボードのベンダーです。
* STMicroelectronics ST33KTPM2XSPI、ST33KTPM2I、ST33TPHF2XSPI (SPI)、ST33TPHF2XI2C (I2C)。
* Microchip ATTPM20 モジュール。
* Nuvoton NPCT650 および NPCT750 TPM 2.0 モジュール。
* Nations Technologies Z32H330 および NS350 TPM 2.0 モジュール。
* SEALSQ QVault TPM 2.0 モジュール (SPI、ポスト量子 ML-DSA および ML-KEM)。
* NVIDIA Jetson Orin (Tegra234) ファームウェア TPM: OP-TEE トラステッドアプリケーションとして動作する TPM 2.0 で、バスではなく Linux カーネルドライバー経由でアクセスします。[System Interfaces](system-interfaces.md) を参照してください。

ファームウェアアップデータは ST33KTPM2A ファームウェアラインも認識しますが、このパーツはテスト済みリストには含まれていません。

デバイスの識別情報は 2 段階で出力されます。バスに直接接続している場合、まず TIS レジスタから読み取った `TPM2: Caps ... Did ... Vid ... Rid` の行が出力されます。続いて `Mfg ...` の行が、製造元、ベンダー文字列、ファームウェアバージョン、認証フラグを報告します。ファームウェア TPM には TIS レジスタがないため、2 行目のみが出力されます。テスト済みの各モジュールの出力例については [TPM 2.0 Overview](tpm2-overview.md) を参照してください。

## サポートされるパーツ

| Vendor | Part(s) | Bus | configure flag | Notes |
| ------ | ------- | --- | -------------- | ----- |
| Infineon | SLB9670 | SPI | `--enable-infineon=slb9670` | ライブラリのデフォルト SPI クロックは 43 MHz です。AES のキーサイズは 128 ビットに制限されます。 |
| Infineon | SLB9672 | SPI | `--enable-infineon` | SPI のデフォルトです。ライブラリのデフォルト SPI クロックは 33 MHz です。ファームウェアアップグレードをサポートします。 |
| Infineon | SLB9673 | I2C | `--enable-infineon=slb9673 --enable-i2c --enable-advio` | I2C 専用のため、SPI クロックは適用されません。 |
| STMicroelectronics | ST33KTPM2XSPI, ST33TPHF2XSPI | SPI | `--enable-st33` | ライブラリのデフォルト SPI クロックは 33 MHz です。ウェイトステートが必要です。 |
| STMicroelectronics | ST33KTPM2I, ST33TPHF2XI2C | I2C | `--enable-st33 --enable-i2c` | ウェイトステートが必要です。ファームウェアアップグレードのサポートはデフォルトで有効です。 |
| Microchip | ATTPM20 | SPI | `--enable-microchip` | ライブラリのデフォルト SPI クロックは 33 MHz です。ウェイトステートが必要です。 |
| Nuvoton | NPCT650, NPCT750 | SPI | `--enable-nuvoton` | ライブラリのデフォルト SPI クロックは 43 MHz です。ウェイトステートが必要です。 |
| Nations Technologies | Z32H330, NS350 | SPI | `--enable-nations` | ウェイトステートが必要です (`WOLFTPM_CHECK_WAIT_STATE`、Nations ビルドでは有効)。 |
| SEALSQ | QVault TPM 2.0 | SPI | `--enable-sealsq` | ライブラリのデフォルト SPI クロックは 33 MHz です。ウェイトステートが必要です。ポスト量子コマンドには `--enable-pqc` または `--enable-v185` も必要です。 |
| NVIDIA | Jetson Orin (Tegra234) firmware TPM | None (kernel driver) | `--enable-autodetect` or `--enable-devtpm` | `/dev/tpmrm0` 経由でアクセスし、存在しない場合は `/dev/tpm0` にフォールバックします。バスのフラグはありません。 |

この表の SPI クロックは `wolftpm/tpm2_types.h` にあるライブラリのデフォルト値であり、各パーツの電気的な上限ではありません。パーツの上限はベンダーのデータシートで定められており、これより低い場合も高い場合もあります。

* **Infineon SLB9670:** 43 MHz が許容されるのは、3.3 V で SCLK エッジが十分に高速な場合のみです。1.8 V の場合やエッジが遅い場合は、上限が低くなります。
* **Infineon SLB9672:** データシートでは、公称 33 MHz、最大 34.65 MHz とされています。
* **STMicroelectronics:** ST33KTPM2X は最大 66 MHz、ST33KTPM2I は最大 48 MHz、ST33TPHF2XSPI は最大 33 MHz をサポートします。wolfTPM はすべての ST パーツで 33 MHz を使用します。
* **Microchip ATTPM20:** 定格は 36 MHz ですが、高い周波数で問題が発生するため、wolfTPM は 33 MHz を使用します。
* **SEALSQ QVault:** データシートは概要で 33 MHz、タイミング表で 36 MHz を記載しています。wolfTPM は保守的な 33 MHz を使用します。

!!! note
    上記のパーツの上限はベンダーのデータシートに基づくものであり、このリポジトリ内のコードとは照合していません。お使いのパーツの最新のデータシートで確認してください。

SPI クロックを変更するには、ビルド時に `TPM2_SPI_MAX_HZ` を定義します。例: `CFLAGS="-DTPM2_SPI_MAX_HZ=20000000"`。選択したベンダーのデフォルト値は `wolftpm/tpm2_types.h` で設定されています。Linux 上の I2C ビルドのデフォルトは 400 kHz (`TPM2_I2C_HZ`) です。

## Autodetect とカーネルデバイス

ベンダーフラグを指定しない場合、`--enable-autodetect` がデフォルトで有効になります。これは実行時にモジュールを検出します。autodetect では、wolfTPM はウェイトステートの確認を有効にし、サポート対象パーツの中で最も低いデフォルト値である 33 MHz に SPI クロックを制限します。この制限は、wolfTPM が直接 SPI アクセスにフォールバックし、`/dev/spidev0.0` から `/dev/spidev0.4` までを試行する場合に適用されます。

Linux では、autodetect と `--enable-devtpm` はまずカーネルの TPM デバイスを試行します。ドライバーは `/dev/tpmrm0` (リソースマネージャー、カーネル 5.12 以降) を開き、存在しない場合は `/dev/tpm0` にフォールバックします。リソースマネージャーのみを使用するには `WOLFTPM_USE_TPMRM` を定義し、特定のデバイスに固定するには `TPM2_LINUX_DEV` を設定します。[System Interfaces](system-interfaces.md) を参照してください。

## ベンダー別ビルド

すべてのビルドは、リポジトリのクローンから始まります。

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
```

### Infineon

SLB9670 または SLB9672 (SPI) と SLB9673 (I2C) をサポートします。次のいずれかを選択してください。

SPI 上の SLB9672 (`--enable-infineon` のデフォルト):

```sh
./autogen.sh
./configure --enable-infineon
make
```

SPI 上の SLB9670:

```sh
./autogen.sh
./configure --enable-infineon=slb9670
make
```

I2C 上の SLB9673:

```sh
./autogen.sh
./configure --enable-infineon=slb9673 --enable-i2c --enable-advio
make
```

### STMicroelectronics ST33

SPI パーツ (ST33KTPM2XSPI、ST33TPHF2XSPI):

```sh
./autogen.sh
./configure --enable-st33
make
```

I2C パーツ (ST33KTPM2I、ST33TPHF2XI2C):

```sh
./autogen.sh
./configure --enable-st33 --enable-i2c
make
```

ファームウェアアップグレードのサポートはデフォルトで有効 (`--enable-firmware`) であり、`st33_fw_update` サンプルツールがビルドされます。除外するには `--disable-firmware` を指定します。

Raspberry Pi の配線: ST33KTPM2X の SPI デバイスは `/dev/spidev0.0` で、nRST (アクティブロー) は GPIO24 (ピン 18) に接続します。Nuvoton は GPIO4 を使用します。必要に応じて、`--enable-hal-reset` と `TPM2_IoCb_Reset()` を使ってコードから nRST を駆動することもできます。[HAL IO Callback](hal-io-callback.md) を参照してください。

### Microchip ATTPM20

```sh
./autogen.sh
./configure --enable-microchip
make
```

### Nuvoton

```sh
./autogen.sh
./configure --enable-nuvoton
make
```

### Nations Technologies

`--enable-nations` を指定してください。指定しない場合、デフォルトの `./configure` は `WOLFTPM_NATIONS` を定義しないため、Nations の設定とベンダーコマンドはビルドされません。Z32H330 と NS350 がテスト済みのモジュールです。NS350 Raspberry Pi TPM 2.0 モジュールは `/dev/spidev0.0` を使用します。ウェイトステートが必要であり、Nations ビルドでは `WOLFTPM_CHECK_WAIT_STATE` によって有効になります。

```sh
./autogen.sh
./configure --enable-nations
make
```

### SEALSQ QVault

通常の TPM コマンドには `--enable-sealsq` を指定してビルドします。ML-DSA と ML-KEM のコマンドは別途制御されているため、`--enable-pqc` (ポスト量子の軽量サブセット) または `--enable-v185` (完全な v1.85 コマンドセット) も指定してください。これらには、ML-DSA と ML-KEM を有効にした wolfSSL ビルドが必要です。ポスト量子のビルドオプションについては [Post-Quantum Support](post-quantum.md) を参照してください。

```sh
./autogen.sh
./configure --enable-sealsq --enable-pqc
make
```

### Espressif ESP-IDF

ESP-IDF コンポーネントには wolfSSL のソースツリーが必要です。CMake が見つけられない場合は、"Could not find wolfssl" というエラーで停止します。wolfSSL のチェックアウトを、`wolfssl`、`wolfssl-master`、または `wolfssl-<user>` という名前の親ディレクトリに配置するか、`WOLFSSL_ROOT` 変数でそのパスを指定してください。代替手段として、wolfSSL ESP Registry のマネージドコンポーネントも利用できます。

wolfTPM 固有の設定は、通常 `[project]/components/wolfssl/include` にある wolfSSL の `user_settings.h` ファイルにあります。

```sh
git clone https://github.com/wolfSSL/wolfssl.git
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF, shown here for VisualGDB using v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. "${WRK_IDF_PATH}/export.sh"
idf.py build
```

## 関連項目

* [HAL IO コールバック](hal-io-callback.md)
* [システムインターフェース](system-interfaces.md)
* [TPM 2.0 の概要](tpm2-overview.md)
* [ポスト量子サポート](post-quantum.md)
