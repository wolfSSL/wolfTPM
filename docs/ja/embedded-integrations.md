# 組み込み向け統合

このページでは、wolfTPM に同梱されているプラットフォームおよび IDE 向けの統合をまとめています。対象は Espressif ESP-IDF、Zephyr、QNX、IAR Embedded Workbench、Visual Studio、Das U-Boot です。STM32 Cube Pack については [STM32CubeIDE](stm32cube.md) を参照してください。

## Espressif ESP-IDF

Espressif 向けプロジェクトは `IDE/Espressif` にあります。wolfTPM 向けの Wolf 固有の設定は、通常 `[project]/components/wolfssl/include` にある wolfSSL の `user_settings.h` ファイルに記述されています。

ESP-IDF が利用可能なシェルからビルドします (ここでは VisualGDB で v5.2 を使用する例を示します)。

```sh
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM/IDE/Espressif

# set your path to ESP-IDF
WRK_IDF_PATH=/mnt/c/SysGCC/esp32/esp-idf/v5.2

. ${WRK_IDF_PATH}/export.sh
idf.py build
```

### メモリ

当初の最小メモリ要件は 35KB のスタックです。`sdkconfig.defaults` を参照してください。現在割り当てられているメモリは 50960 です。

### ピン割り当て (I2C)

既定では次のピン割り当てが使用されます。`menuconfig` で変更できます。

| | SDA | SCL |
| --- | --- | --- |
| ESP I2C Master | I2C_MASTER_SDA | I2C_MASTER_SCL |
| TPM2 Device | SDA | SCL |

`I2C_MASTER_SDA` と `I2C_MASTER_SCL` の既定値については、`menuconfig` の `Example Configuration` を参照してください。ドライバーが内部プルアップを有効にするため、SDA と SCL に外付けのプルアップ抵抗は不要です。

### I2C のトラブルシューティング

- I2C トランザクション中に UART へ出力すると、タイミングに影響してエラーが発生することがあります。
- フラッシュ更新後に TPM モジュールがリセットされていることを確認してください。
- 配線を確認してください。`SCL` は `SCL` に、`SDA` は `SDA` に接続します。GND も接続してください。Vcc は 3.3V のみです。
- ESP32 側で正しいピンが接続されていることを確認してください。既定の SCL は `GPIO 19`、既定の SDA は `GPIO 18` です。
- 他の I2C ボードと併用する前に、I2C デバイス 1 台だけでテストしてください。
- 複数の I2C ボードを使用する場合は、適切なプルアップがあるか確認してください。データシートを参照してください。
- TPM デバイスをもう一度リセットしてください。TPM SLB9673 評価ボードのボタンを押すか、必要に応じて TPM のピン 17 を設定します。

## Zephyr

Zephyr ポートは wolfTPM のソースツリーの `zephyr` ディレクトリにあります。[Zephyr Project](https://www.zephyrproject.org/) を対象とし、次を提供します。

| パス | 内容 |
| --- | --- |
| `modules/lib/wolftpm` | wolfTPM ライブラリのコード |
| `modules/lib/wolftpm/zephyr/` | wolfTPM を Zephyr モジュールとして使うための設定ファイルと CMake ファイル |
| `modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps` | wolfTPM ケイパビリティのサンプルアプリケーション |
| `modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test` | wolfTPM ラッパーテストアプリケーション |

### Zephyr モジュールとしてセットアップする

[Zephyr getting started guide](https://docs.zephyrproject.org/latest/develop/getting_started/index.html) に従って Zephyr プロジェクトをセットアップします。その後、`west.yml` に wolfTPM をプロジェクトとして追加します。

```yaml
manifest:
  remotes:
    # <your other remotes>
    - name: wolftpm
      url-base: https://github.com/wolfssl

  projects:
    # <your other projects>
    - name: wolftpm
      path: modules/lib/wolftpm
      revision: master
      remote: wolftpm
```

!!! note
    wolfTPM は wolfSSL に依存するため、同じ方法で `west.yml` に wolfSSL も追加してください。

west のモジュールを更新します。

```sh
west update
```

これで west は wolftpm をモジュールとして認識し、その Kconfig と `CMakeLists.txt` をビルドシステムに取り込みます。

### ラッパーテストをビルドして実行する

`west zephyr-export` を実行せずにアプリをビルドするには、`CMAKE_PREFIX_PATH` を Zephyr SDK の場所に設定し、`zephyr` ディレクトリからビルドします。例:

```sh
CMAKE_PREFIX_PATH=/path/to/zephyr-sdk-<VERSION> west build -p always -b qemu_x86 ../modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test/
```

`wolftpm_wrap_test` をビルドして実行します。

```sh
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_test
west build -t run
```

### ケイパビリティサンプルをビルドして実行する

`wolftpm_wrap_caps` をビルドして実行します。

```sh
cd [zephyrproject]
west build -p auto -b qemu_x86 modules/lib/wolftpm/zephyr/samples/wolftpm_wrap_caps
west build -t run
```

## QNX

以下の手順では、QNX SPI ドライバー経由で wolfTPM を使用する QNX Momentics プロジェクトを作成します。ファイルは `IDE/QNX` にあります。

### QNX アプリケーションを作成する

1. ライブラリ用 (`lib`) とインクルード用 (`inc`) のフォルダーを作成します。
2. ライブラリのソースを `wolfssl` と `wolftpm` として `lib` ディレクトリに追加します。
3. ソースとインクルードディレクトリをビルドするように Makefile を編集します。

```
# wolfSSL and wolfTPM library includes/sources
INCLUDES += -I./inc -I./lib/wolftpm -I./lib/wolfssl
CCFLAGS_all += -DWOLFSSL_USER_SETTINGS -DWOLFTPM_USER_SETTINGS

SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/*.c)
SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/port/arm/*.c)
SRCS += $(call wildcard, lib/wolfssl/wolfcrypt/src/port/xilinx/*.c)
SRCS += $(call wildcard, lib/wolftpm/src/*.c)

# The QNX SPI Driver
LIBS += -lspi-master
```

4. すべての Wolf 固有の設定を記述する `inc/user_settings.h` を作成します。テンプレートは次のとおりです。

```c
#ifndef WOLF_USER_SETTINGS_H
#define WOLF_USER_SETTINGS_H

/* TPM */
#define WOLFTPM_AUTODETECT
#define WOLFTPM_CHECK_WAIT_STATE
#define WOLFTPM_ADV_IO /* use advanced IO HAL callback */
#define TPM_TIMEOUT_TRIES 100000

/* always perform self-test (some chips require) */
#define WOLFTPM_PERFORM_SELFTEST

/* Reduce stack use */
#define MAX_COMMAND_SIZE    1024
#define MAX_RESPONSE_SIZE   1350
#define MAX_DIGEST_BUFFER   896

/* Debugging */
#if 1
   #define DEBUG_WOLFTPM
   //#define WOLFTPM_DEBUG_VERBOSE
   //#define WOLFTPM_DEBUG_IO
   //#define WOLFTPM_DEBUG_TIMEOUT
#endif

/* Platform */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MAX

/* Math */
#define ECC_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT
#define USE_FAST_MATH
#define FP_MAX_BITS (2 * 4096)
#define WOLFSSL_NO_HASH_RAW
#define ALT_ECC_SIZE

/* Enables */
#define HAVE_ECC
#define ECC_SHAMIR
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

/* Disables */
#define NO_MAIN_DRIVER
#define NO_WOLFSSL_MEMORY
#define NO_ASN
#define NO_ASN_TIME
#define NO_CODING
#define NO_CERTS
#define NO_PSK

#define NO_PWDBASED
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_HC128
#define NO_RABBIT
#define NO_DES3

#endif /* !WOLF_USER_SETTINGS_H */
```

5. wolfTPM の HAL には、`tpm_io.c` をそのまま使用するか、必要な HAL インターフェースを自身の `.c` ファイルにコピーします。[HAL I/O Callback](hal-io-callback.md) を参照してください。
6. wolfTPM のサンプルコードを自身の `.c` ファイルに追加します。
7. 以下の QNX BSP SPI マスターパッチの適用を検討してください。これにより、チップセレクトをアサートしたまま複数の呼び出しを実行できるようになります。これは SPI のウェイトステートに必要です。

### 手動チップセレクト用の QNX SPI マスターパッチ

次の QNX BSP ファイルを編集します。

1. `bsp/src/hardware/spi/xzynq/aarch64/dll.le.zcu102/xzynq_spi.c`:

```diff
@@ -442,7 +442,7 @@ static void xzynq_setup(xzynq_spi_t *dev, uint32_t device)
     spi_debug1("%s: CONFIG_SPI_REG = 0x%x", __func__, dev->ctrl[id]);
 #endif

-    if(dev->fcs) {
+    if(dev->fcs || (devlist[id].cfg.mode & SPI_MODE_MAN_CS)) {
         out32(base + XZYNQ_SPI_CR_OFFSET, dev->ctrl[id] | XZYNQ_SPI_CR_MAN_CS);
     } else {
         out32(base + XZYNQ_SPI_CR_OFFSET, dev->ctrl[id]);
@@ -621,7 +621,7 @@ void *xzynq_xfer(void *hdl, uint32_t device, uint8_t *buf, int *len)
         reset = 1;
     }

-    if(!dev->fcs) {
+    if(!dev->fcs && !(devlist[id].cfg.mode & SPI_MODE_MAN_CS)) {
         xzynq_spi_slave_select(dev, id, 0);
     }
```

2. `bsp/src/hardware/spi/xzynq/config.c`:

```diff
@@ -72,6 +73,16 @@ int xzynq_cfg(void *hdl, spi_cfg_t *cfg, int cs)
     /* Enable ModeFail generation */
     ctrl |= XZYNQ_SPI_CR_MFAIL_EN;

+    if (cfg->mode & SPI_MODE_MAN_CS)
+        ctrl |= XZYNQ_SPI_CR_MAN_CS; /* enable manual CS mode */
+
+    if (cfg->mode & SPI_MODE_CLEAR_CS) {
+        /* make sure all chip selects are de-asserted */
+        /* set all CS bits high to de-assert */
+        out32(base + XZYNQ_SPI_CR_OFFSET,
+            in32(base + XZYNQ_SPI_CR_OFFSET) | XZYNQ_SPI_CR_CS);
+    }
+
```

3. `target/qnx7/usr/include/hw/spi-master.h`:

```diff
@@ -71,6 +71,8 @@ typedef struct {
 #define	SPI_MODE_RDY_LEVEL		(2 << 14)	/* Low level signal */
 #define	SPI_MODE_IDLE_INSERT	(1 << 16)
+#define	SPI_MODE_MAN_CS			(1 << 17)   /* Manual Chip select */
+#define	SPI_MODE_CLEAR_CS		(1 << 18)   /* Clear all chip selects (used with SPI_MODE_MAN_CS) */

 #define	SPI_MODE_LOCKED			(1 << 31)	/* The device is locked by another client */
```

ご質問は support@wolfssl.com までメールでお問い合わせください。

## IAR-EWARM

`IDE/IAR-EWARM` ディレクトリには、TPM 2.0 ラッパー API 向けの IAR Embedded Workbench for ARM プロジェクトが含まれています。README はありません。

| パス | 内容 |
| --- | --- |
| `ewarm-tpm2.eww` | IAR ワークスペース |
| `ewarm-tpm2.ewp` | IAR プロジェクト |
| `source/main.c` | アプリケーションのエントリポイント |
| `source/tpm_main.c` | `wolftpm/tpm2.h` と `wolftpm/tpm2_wrap.h` を使用する TPM サンプルコード |
| `header/tpm_main.h` | サンプルコード用のヘッダー |

ビルドするには、IAR Embedded Workbench で `ewarm-tpm2.eww` を開きます。このサンプルは、ストレージ鍵 (`0x81000000`)、RSA 鍵 (`0x81000010`)、RSA 公開鍵 (`0x81000011`)、および NV 証明書インデックス (`0x01800000`) に固定のハンドルを使用します。

!!! note
    このセクションは拡充が必要です。必要な wolfSSL と wolfTPM の設定、使用する HAL、および動作確認済みの IAR バージョンを追記する必要があります。

## Visual Studio

`IDE/VisualStudio` ディレクトリには、wolfSSL、wolfTPM、およびいくつかのサンプルをビルドするプロジェクトを含む Visual Studio ソリューション `wolftpm.sln` があります。プロジェクトは `wolfssl.vcxproj`、`wolftpm.vcxproj`、`wrap_test.vcxproj`、`wolfcrypt_test.vcxproj`、`tls_server.vcxproj` です。ソリューションとプロジェクトは Visual Studio 2015 をベースにしており、開く際に新しいバージョンへ再ターゲットできます。

すべてのビルド設定は `IDE/VisualStudio/user_settings.h` にあります。プロジェクトは、`wolftpm` と `wolfssl` の各ディレクトリが隣り合って配置されていることを前提としています。

このソリューションは、wolfSSL の Web サイトから入手できる FIPS Ready バンドルに対応しています。使用するには、`user_settings.h` の `#if 0` となっている FIPS セクションを有効にします。実行時に `fips_test.c` で FIPS の整合性チェックを設定する方法については、wolfSSL ソース内の `wolfssl/IDE/WIN10/README.txt` を参照してください。

!!! note
    このセクションは拡充が必要です。具体的なビルド手順と、Windows で使用する TPM インターフェースを追記する必要があります。TBS については [Windows TBS](system-interfaces.md) を参照してください。

## U-Boot

wolfTPM は Das U-Boot を実験的にサポートしており、次の機能があります。

- TPM との通信に U-Boot のソフトウェア SPI ドライバーを使用します。
- 内部の TIS レイヤーを通じて TPM 2.0 ドライバーの機能を実装します。
- すべての TPM 2.0 コマンドへのネイティブ API アクセスを提供します。
- 一般的な TPM 2.0 操作向けのラッパー API を含みます。
- 2 つの統合パスをサポートします。
  - `__linux__`: `tpm2_linux.c` を通じて既存の tpm インターフェースを使用します。
  - `__UBOOT__`: `tpm_io_uboot.c` を通じた直接の SPI 通信を行います。

サンプルファイルは `examples/u-boot` にあります。

### U-Boot コマンド

これらのコマンドは `wolftpm` インターフェースから利用できます。

基本コマンド:

| コマンド | 説明 |
| --- | --- |
| `help` | ヘルプテキストを表示します。 |
| `device [num device]` | すべてのデバイスを表示するか、指定したデバイスを設定します。 |
| `info` | TPM に関する情報を表示します。 |
| `state` | 利用可能な場合に、TPM の内部状態を表示します。 |
| `autostart` | TPM を初期化し、Startup(clear) を実行し、完全なセルフテストシーケンスを実行します。 |
| `init` | ソフトウェアスタックを初期化します。最初のコマンドでなければなりません。 |
| `startup <mode> [<op>]` | TPM2_Startup コマンドを発行します。`<mode>` は `TPM2_SU_CLEAR` (状態をリセット) または `TPM2_SU_STATE` (状態を保持) です。`[<op>]` は "off" を指定するオプションのシャットダウンです。 |
| `self_test <type>` | TPM の機能をテストします。`<type>` は "full" (すべてのテスト) または "continue" (未テストのテストのみ) です。 |

PCR 操作:

| コマンド | 説明 |
| --- | --- |
| `pcr_extend <pcr> <digest_addr> [<digest_algo>]` | ダイジェストで PCR を拡張します。 |
| `pcr_read <pcr> <digest_addr> [<digest_algo>]` | PCR をメモリに読み出します。 |
| `pcr_allocate <algorithm> <on/off> [<password>]` | PCR バンクのアルゴリズムを再構成します。 |
| `pcr_setauthpolicy` or `pcr_setauthvalue <pcr> <key> [<password>]` | PCR アクセスキーを変更します。 |
| `pcr_print` | 現在の PCR の状態を表示します。 |

セキュリティ管理:

| コマンド | 説明 |
| --- | --- |
| `clear <hierarchy>` | TPM2_Clear を発行します。`<hierarchy>` は `TPM2_RH_LOCKOUT` または `TPM2_RH_PLATFORM` です。 |
| `change_auth <hierarchy> <new_pw> [<old_pw>]` | 階層のパスワードを変更します。`<hierarchy>` は `TPM2_RH_LOCKOUT`、`TPM2_RH_ENDORSEMENT`、`TPM2_RH_OWNER`、または `TPM2_RH_PLATFORM` です。 |
| `dam_reset [<password>]` | 内部エラーカウンターをリセットします。 |
| `dam_parameters <max_tries> <recovery_time> <lockout_recovery> [<password>]` | ディクショナリアタック軽減 (DAM) のパラメータを設定します。 |
| `caps` | TPM のケイパビリティと情報を表示します。 |

ファームウェア管理:

| コマンド | 説明 |
| --- | --- |
| `firmware_update <manifest_addr> <manifest_sz> <firmware_addr> <firmware_sz>` | TPM ファームウェアを更新します。 |
| `firmware_cancel` | TPM ファームウェアの更新をキャンセルします。 |

### U-Boot で wolfTPM を有効にする

ボードの defconfig に次のオプションを追加します。

```
CONFIG_TPM=y
CONFIG_TPM_V2=y
CONFIG_TPM_WOLF=y
CONFIG_CMD_WOLFTPM=y
```

あるいは、`make menuconfig` を使用して次を有効にします。

- Device Drivers, TPM, TPM 2.0 Support
- Device Drivers, TPM, wolfTPM Support
- Command line interface, Security commands, Enable wolfTPM commands

### QEMU でビルドして実行する

この手順では、TPM シミュレータを使用して、QEMU 上で wolfTPM 付きの U-Boot を実行します。

1. swtpm をインストールします。

```sh
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make
```

2. U-Boot をビルドします。

```sh
make distclean
export CROSS_COMPILE=aarch64-linux-gnu-
export ARCH=aarch64
make qemu_arm64_defconfig
make -j4
```

3. TPM の状態ディレクトリを作成します。

```sh
mkdir -p /tmp/mytpm1
```

4. 1 つ目のターミナルで swtpm を起動します。

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/mytpm1 --ctrl type=unixio,path=/tmp/mytpm1/swtpm-sock --log level=20
```

5. 2 つ目のターミナルで QEMU を起動します。

```sh
qemu-system-aarch64 -machine virt -nographic -cpu cortex-a57 -bios u-boot.bin -chardev socket,id=chrtpm,path=/tmp/mytpm1/swtpm-sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis-device,tpmdev=tpm0
```

6. ブート出力の例:

```
U-Boot 2025.07-rc1-ge15cbf232ddf-dirty (May 06 2025 - 16:25:56 -0700)

DRAM:  128 MiB
using memory 0x46658000-0x47698000 for malloc()
Core:  52 devices, 15 uclasses, devicetree: board
Flash: 64 MiB
Loading Environment from Flash... *** Warning - bad CRC, using default environment

In:    serial,usbkbd
Out:   serial,vidconsole
Err:   serial,vidconsole
No USB controllers found
Net:   eth0: virtio-net#32

Hit any key to stop autoboot:  0
=> tpm2 help
tpm2 - Issue a TPMv2.x command

Usage:
tpm2 <command> [<arguments>]

device [num device]
    Show all devices or set the specified device
info
    Show information about the TPM.
```

7. コマンドの例:

```
=> tpm2 info
tpm_tis@0 v2.0: VendorID 0x1014, DeviceID 0x0001, RevisionID 0x01 [open]
=> tpm2 startup TPM2_SU_CLEAR
=> tpm2 get_capability 0x6 0x20e 0x200 1
Capabilities read from TPM:
Property 0x6a2e45a9: 0x6c3646a9
=> tpm2 pcr_read 10 0x100000
PCR #10 sha256 32 byte content (20 known updates):
 20 25 73 0a 00 56 61 6c 75 65 3a 0a 00 23 23 20
 4f 75 74 20 6f 66 20 6d 65 6d 6f 72 79 0a 00 23
```

8. QEMU を終了するには、Ctrl-A に続けて X を押します。

## 関連項目

- [STM32CubeIDE](stm32cube.md)
- [Building](building.md)
- [System Interfaces](system-interfaces.md)
- [HAL I/O Callback](hal-io-callback.md)
- [Supported Hardware](supported-hardware.md)
- [Windows TBS](system-interfaces.md)
