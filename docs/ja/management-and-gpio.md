# 管理ユーティリティと GPIO

このページでは、`examples/management/` にある小規模な TPM 管理ユーティリティと、`examples/gpio/` にある GPIO 制御のサンプルを説明します。

## 管理ユーティリティ

| プログラム | 目的 |
|---------|---------|
| `da_check.c` | ディクショナリアタック (DA) ロックアウトのチェック。DA で保護されたキーと noDA キーを使用し、不正な認可を繰り返してロックアウト状態に入り、ロックアウトリセットで復旧します。 |
| `flush.c` | トランジェントハンドルと永続ハンドルをフラッシュします。ハンドル (例: `0x80000000`) を指定して実行するとそのオブジェクトを解放し、パラメータなしで実行すると一般的なトランジェントオブジェクト (トランジェントキー、ポリシーセッション、HMAC セッション) をフラッシュします。 |
| `tpmclear.c` | `TPM2_Clear` を実行して階層をクリアします。 |

```sh
./examples/management/da_check
./examples/management/flush [handle]
./examples/management/tpmclear
```

!!! warning
    `tpmclear` は TPM をクリアします。クリアされた階層配下のキーとデータは失われます。

## GPIO 制御

一部の TPM 2.0 モジュールには、開発者が利用できる追加の I/O 機能と GPIO があります。この追加 GPIO を使って、セキュリティイベントやシステム状態を他のサブシステムに通知できます。

!!! note
    GPIO 制御のサンプルがサポートするのは、ST33 および NPCT75x TPM 2.0 モジュールのみです。

`examples/gpio/` には 3 つのプログラムがあります。

| プログラム | 目的 |
|---------|---------|
| `gpio_config.c` | GPIO を設定します。 |
| `gpio_set.c` | 設定済みの GPIO を High または Low に設定します。 |
| `gpio_read.c` | 設定済みの GPIO のレベルを読み取ります。 |

すべてのサンプルにヘルプオプション `-h` があります。`gpio_config -h` を実行すると GPIO のモードを確認できます。パラメータを指定しない場合はデモ用の使い方で実行されます。GPIO は物理世界と相互作用するため、オプションは慎重に選択してください。

### GPIO の設定 (ST33)

ST33 は 6 つのモードをサポートします。`gpio_config` のヘルプ出力は次のとおりです。

```sh
$ ./examples/gpio/gpio_config -h
Expected usage:
./examples/gpio/gpio_config [num] [mode]
* num is a GPIO number between 0-3 (default 0)
* mode is a number selecting the GPIO mode between 0-6 (default 3):
	0. standard - reset to the GPIO's default mode
	1. floating - input in floating configuration.
	2. pullup   - input with pull up enabled
	3. pulldown - input with pull down enabled
	4. opendrain - output in open drain configuration
	5. pushpull  - output in push pull configuration
	6. unconfigure - delete the NV index for the selected GPIO
Example usage, without parameters, configures GPIO0 as input with a pull down.
```

GPIO を出力として設定します。

```sh
$ ./examples/gpio/gpio_config 0 5
GPIO num is: 0
GPIO mode is: 5
Example how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

GPIO をプルダウン付きの入力として設定します (モード 3)。

```sh
$ ./examples/gpio/gpio_config 0 3
GPIO num is: 0
GPIO mode is: 3
Demo how to use extra GPIO on a TPM 2.0 modules
Trying to configure GPIO0...
TPM2_GPIO_Config success
NV Index for GPIO access created
```

### GPIO の設定 (NPCT75xx)

NPCT75x は 3 つの出力モードをサポートし、入力モードはありません。`gpio_config` のヘルプ出力は次のとおりです。

```sh
$ ./examples/gpio/gpio_config -h
Expected usage:
./examples/gpio/gpio_config [num] [mode]
* num is a GPIO number between 3 and 4 (default 3)
* mode is either push-pull, open-drain or open-drain with pull-up
	1. pushpull  - output in push pull configuration
	2. opendrain - output in open drain configuration
	3. pullup - output in open drain with pull-up enabled
	4. unconfig - delete NV index for GPIO access
Example usage, without parameters, configures GPIO3 as push-pull output.
```

NPCT75x の GPIO 番号は GPIO3 から始まりますが、ST33 は GPIO0 から始まります。

```sh
$ ./examples/gpio/gpio_config 4 1
Example for GPIO configuration of a NPTC7xx TPM 2.0 module
GPIO number: 4
GPIO mode: 1
Successfully read the current configuration
Successfully wrote new configuration
NV Index for GPIO access created
```

### GPIO の使用方法

GPIO の設定を切り替える手順は次のとおりです。

- ST33 の場合、`gpio_config` は既存の NV インデックスを削除するため、新しい GPIO 設定を選択できます。
- NPCT75xx の場合、`gpio_config` は作成済みの NV インデックスを削除せずに任意の GPIO を再設定できます。

設定後、GPIO を設定および読み取ります。

```sh
$ ./examples/gpio/gpio_set 0 -high
GPIO0 set to high level

$ ./examples/gpio/gpio_set 0 -low
GPIO0 set to low level

$ ./examples/gpio/gpio_read 0
GPIO0 is Low
```

## 関連項目

- [Sealing and NVRAM](sealing-and-nvram.md)
- [TLS and certificates](tls-and-certificates.md)
- [Firmware update](firmware-update.md)
- [Supported hardware](supported-hardware.md)
