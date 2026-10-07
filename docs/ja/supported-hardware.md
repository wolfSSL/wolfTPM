# サポート対象ハードウェア

wolfTPM は、単一の HAL IO コールバックを介して SPI または I2C 経由で TPM 2.0 デバイスと通信するか、オペレーティングシステムのドライバ経由でシステム TPM と通信します。このページでは、サンプルで使用するプラットフォーム、wolfTPM でテスト済みのハードウェア、各デバイスに対応する configure フラグ、およびベンダーごとのビルド手順を説明します。

## プラットフォーム

このライブラリのサンプルは Raspberry Pi 上で使用することを想定して作成されており、Linux の `spidev` インターフェース (`/dev/spidev0.0`) を使用します。

ハードウェアバス (SPI または I2C) とのインターフェースには、単一の HAL コールバックを使用します。このコールバックは、`TPM2_Init` または `wolfTPM2_Init` を呼び出す際の初期化時に設定されます。コールバックモデルについては [HAL IO コールバック](hal-io-callback.md) を参照してください。

HAL の実装例が `hal` ディレクトリに用意されています。対象は次のとおりです。

* Atmel ASF
* Barebox
* Espressif ESP-IDF
* Infineon TriCore
* Linux
* STM32 CubeMX
* wolfHAL
* Xilinx

拡張 IO オプション (`--enable-advio` または `WOLFTPM_ADV_IO`) を使用すると、レジスタアドレスと読み書きフラグが IO コールバックのパラメータとして追加されます。これは I2C サポートに必要です。

## テスト済みハードウェア

wolfTPM は次のハードウェアでテストされています。

* Infineon OPTIGA(TM) Trusted Platform Module 2.0 SLB9670、SLB9672、SLB9673 (I2C)。
    * LetsTrust は TPM 開発ボードのベンダーです (http://letstrust.de)。
* STMicro STSAFE-TPM、ST33TPHF2XSPI、ST33TPHF2XI2C、ST33KTPM2X (SPI および I2C)
* Microchip ATTPM20 モジュール
* Nuvoton NPCT65X または NPCT75x TPM 2.0 モジュール
* Nations Technologies Z32H330 または NS350 TPM 2.0 モジュール
* SealSQ QVault TPM 2.0 モジュール (SPI、ポスト量子 ML-DSA および ML-KEM)
* NVIDIA Jetson Orin (Tegra234) ファームウェア TPM: OP-TEE トラステッドアプリケーションとして動作する TPM 2.0 で、バスではなく Linux カーネルドライバ経由でアクセスします。ソースツリー内の `docs/DEVTPM.md` を参照してください。

サンプルの出力の最初の行にデバイスが識別されます (機能、デバイス ID、ベンダー ID、リビジョン、ファームウェアバージョン)。デバイス識別情報の取得方法と読み方については [TPM 2.0 概要](tpm2-overview.md) を参照してください。

## サポート対象デバイス

| ベンダー | デバイス | バス | configure フラグ | 備考 |
| ------ | ------- | --- | -------------- | ----- |
| Infineon | SLB9670 | SPI | `--enable-infineon=slb9670` | SPI クロックの最大値は 43 MHz。ウェイトステートは不要。AES 鍵サイズは 128 ビットに制限されます。 |
| Infineon | SLB9672 | SPI | `--enable-infineon` | SPI のデフォルト。SPI クロックの最大値は 33 MHz。ファームウェアアップグレードをサポートします。 |
| Infineon | SLB9673 | I2C | `--enable-infineon --enable-i2c` | I2C のデフォルト。SLB9672 の SPI クロックのデフォルト値を使用します。 |
| STMicro | ST33KTPM2X, ST33TPHF2X | SPI または I2C | `--enable-st33 [--enable-i2c] [--enable-firmware]` | SPI クロックの最大値は 33 MHz。ウェイトステートが必要です。`--enable-firmware` を指定すると `st33_fw_update` ツールが追加されます。 |
| Microchip | ATTPM20 | SPI | `--enable-microchip` | 定格は 36 MHz ですが、高いクロックレートで問題が発生するため、wolfTPM は 33 MHz を使用します。ウェイトステートが必要です。 |
| Nuvoton | NPCT650, NPCT750 | SPI | `--enable-nuvoton` | SPI クロックの最大値は 43 MHz。ウェイトステートが必要です。 |
| Nations Technologies | Z32H330, NS350 | SPI | `--enable-nations` | NS350 には `WOLFTPM_CHECK_WAIT_STATE` が必要です (デフォルトで有効)。 |
| SealSQ | QVault TPM 2.0 | SPI | `--enable-sealsq` | ポスト量子アルゴリズムをシリコンに実装。SPI クロックの最大値は 33 MHz。ウェイトステートが必要です。 |
| NVIDIA | Jetson Orin (Tegra234) ファームウェア TPM | なし (カーネルドライバ) | `--enable-autodetect` または `--enable-devtpm` | `/dev/tpmrm0` 経由でアクセスします。バスのフラグは不要です。 |

!!! note
    `--enable-autodetect` を指定すると、wolfTPM はウェイトステートのチェックを有効にし、SPI クロックをサポート対象デバイスの中で最も低い最大値である 33 MHz に制限します。

上記の SPI クロックの上限は、`wolftpm/tpm2_types.h` に定義されている各デバイスのデフォルト値です。`TPM2_SPI_MAX_HZ` を定義することで上書きできます。

## ベンダー別のビルド

すべてのビルドは、リポジトリのクローンから始まります。

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
```

### Infineon

SLB9670 または SLB9672 (SPI)、および SLB9673 (I2C) をサポートします。

```sh
./autogen.sh
./configure --enable-infineon [--enable-i2c]
make
```

デフォルトは SLB9672 (SPI)、または I2C を有効にした場合は SLB9673 です。SLB9670 を選択するには、`--enable-infineon=slb9670` を使用します。

### ST ST33

```sh
./autogen.sh
./configure --enable-st33 [--enable-i2c] [--enable-firmware]
make
```

`--enable-firmware` オプションは、ST33 TPM のファームウェアアップグレードサポートを有効にします。これにより `st33_fw_update` サンプルツールが追加されます。

Raspberry Pi の配線: ST33KTPM2X の SPI デバイスは `/dev/spidev0.0` で、nRST (アクティブロー) は GPIO24 (ピン 18) に接続します。Nuvoton は GPIO4 を使用します。`--enable-hal-reset` と `TPM2_IoCb_Reset()` を使用して、コードから nRST を制御することもできます。[HAL IO コールバック](hal-io-callback.md) を参照してください。

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

`./configure` はデフォルトのまま使用します。すべての Nations TPM 2.0 モジュールは互換性があり、`--enable-nations` によってデバイス固有の設定が選択されます。NS350 Raspberry Pi TPM 2.0 モジュールは `/dev/spidev0.0` を使用します。TPM のウェイトステートが必要で、`WOLFTPM_CHECK_WAIT_STATE` によりデフォルトで有効になっています。

### SealSQ QVault

`--enable-sealsq` を指定してビルドします。ポスト量子関連のビルドオプションについては [ポスト量子サポート](post-quantum.md) で説明しています。

### Espressif ESP-IDF

wolfTPM 固有の設定は、wolfSSL の `user_settings.h` ファイルを参照してください。通常は `[project]/components/wolfssl/include` にあります。

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF, shown here for VisualGDB using v5.2
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. ${WRK_IDF_PATH}/export.sh
idf.py build
```

## 関連項目

* [HAL IO コールバック](hal-io-callback.md)
* [TPM 2.0 概要](tpm2-overview.md)
* [ポスト量子サポート](post-quantum.md)
