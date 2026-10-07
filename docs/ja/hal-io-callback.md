# HAL IO コールバック

TPM ハードウェアとの通信を処理するために、単一のハードウェア抽象化レイヤー (HAL) コールバックを登録する必要があります。このページでは、コールバック、wolfTPM に同梱されている実装例、およびそれらを制御するビルドオプションについて説明します。

初期セットアップを支援するため、複数のプラットフォーム向けのサンプルが用意されています。システムが提供する組み込みのハードウェアインターフェースを使用する場合は、HAL IO コールバックとして `NULL` を指定できます。

利用可能なシステム TPM インターフェースは次のとおりです。

* Linux `/dev/tpm0`: `WOLFTPM_LINUX_DEV` または `--enable-devtpm` で有効化します。
* Windows TBS: `WOLFTPM_WINAPI` または `--enable-winapi` で有効化します。
* ソフトウェア TPM シミュレータ: `WOLFTPM_SWTPM` または `--enable-swtpm` で有効化します。

HAL IO コールバックを使用する場合は、ライブラリの初期化時に次の関数で登録します。

* TPM2 ネイティブ API: `TPM2_Init`
* wolfTPM ラッパー: `wolfTPM2_Init`

## HAL 実装例

| プラットフォーム | サンプルファイル | ビルドオプション |
| -------- | ------------ | ------------ |
| Atmel ASF | `tpm_io_atmel.c` | `WOLFSSL_ATMEL` |
| Barebox | `tpm_io_barebox.c` | `__BAREBOX__` |
| Infineon | `tpm_io_infineon.c` | `WOLFTPM_INFINEON_TRICORE` |
| Linux | `tpm_io_linux.c` | `__linux__` |
| Microchip | `tpm_io_microchip.c` | `WOLFTPM_MICROCHIP_HARMONY` |
| QNX | `tpm_io_qnx.c` | `__QNX__` |
| ST Cube HAL | `tpm_io_st.c` | `WOLFSSL_STM32_CUBEMX` |
| wolfHAL | `tpm_io_wolfhal.c` | `WOLFTPM_WOLFHAL` |
| Xilinx | `tpm_io_xilinx.c` | `__XILINX__` |

## wolfHAL

`WOLFTPM_WOLFHAL` または `--enable-wolfhal` で有効化します。wolfHAL のヘッダーがインクルードパス上にある必要があります。

この HAL はプラットフォーム選択チェーンの最後に配置されているため、他のプラットフォームマクロが定義されていない場合にのみ使用されます。たとえば、CubeMX のヘッダーが存在する STM32 ターゲット向けにビルドすると、代わりに `tpm_io_st.c` が選択されます。

### ボード定義

wolfTPM はボード定義を同梱していません。`tpm_io_wolfhal.c` は `"board.h"` をインクルードするため、アプリケーション側でインクルードパス上に用意する必要があります。wolfHAL のプロジェクトにはすでに存在するため、ほとんどの場合は、以下の TPM 固有のエントリを追加するだけで済みます。

SPI の場合:

| マクロ | 型 | 説明 |
| ----- | ---- | ----------- |
| `BOARD_SPI_DEV` | `whal_Spi*` | TPM が接続されている SPI インスタンス |
| `BOARD_SPI_COM_CFG` | `whal_Spi_ComCfg*` | SPI セッションパラメータ |
| `BOARD_GPIO_DEV` | `whal_Gpio*` | チップセレクトを駆動する GPIO インスタンス |
| `BOARD_CS_PIN` | ピン番号 | チップセレクトピン (アクティブローで駆動) |

I2C の場合 (`--enable-i2c` が設定する `WOLFTPM_ADV_IO` も必要):

| マクロ | 型 | 説明 |
| ----- | ---- | ----------- |
| `BOARD_I2C_DEV` | `whal_I2c*` | TPM が接続されている I2C インスタンス |
| `BOARD_I2C_COM_CFG` | `whal_I2c_ComCfg*` | TPM のターゲットアドレスを含む I2C セッションパラメータ |

TPM のターゲットアドレスは `BOARD_I2C_COM_CFG` の `addr` フィールドに設定します。ほとんどの TPM 2.0 I2C デバイスは `0x2e` を使用します。他の I2C HAL が使用する `TPM2_I2C_ADDR` マクロはここでは効果がないため、定義するとコンパイルエラーになります。

TPM 2.0 の I2C デバイスは、ウェイクアップに約 80 us かかり、準備ができるまで NAK を返すため、各転送は最大 `TPM_I2C_TRIES` 回 (デフォルトは 10) 再試行されます。この回数を変更するには `TPM_I2C_TRIES` を定義します。

エントリが不足している場合は、必要なマクロ名を示すメッセージとともにコンパイル時に報告されます。選択したバスで必要なマクロのみがチェックされます。

既存の wolfHAL `board.h` への追加例:

```c
/* TPM on SPI1, chip select on PA15 */
extern whal_Spi_ComCfg g_tpmSpiComCfg;
#define BOARD_SPI_COM_CFG  (&g_tpmSpiComCfg)
#define BOARD_CS_PIN       15
```

I2C の場合は、セッション設定に TPM アドレスを含めます。

```c
/* board.c */
whal_I2c_ComCfg g_tpmI2cComCfg = {
    .freq   = 400000, /* Hz */
    .addr   = 0x2e,   /* TPM target address */
    .addrSz = 7,      /* bits */
};

/* board.h */
extern whal_I2c_ComCfg g_tpmI2cComCfg;
#define BOARD_I2C_COM_CFG  (&g_tpmI2cComCfg)
```

## HAL IO コールバック関数

HAL コールバック関数のプロトタイプ:

```c
#ifdef WOLFTPM_ADV_IO
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz, void* userCtx);
#else
typedef int (*TPM2HalIoCb)(struct TPM2_CTX*, const BYTE* txBuf, BYTE* rxBuf,
    UINT16 xferSz, void* userCtx);
#endif
```

関数定義の例:

```c
#ifdef WOLFTPM_ADV_IO
int TPM2_IoCb(TPM2_CTX*, int isRead, word32 addr, byte* buf, word16 size,
    void* userCtx);
#else
int TPM2_IoCb(TPM2_CTX* ctx, const byte* txBuf, byte* rxBuf,
    word16 xferSz, void* userCtx);
#endif
```

## 追加のビルドオプション

* `WOLFTPM_CHECK_WAIT_STATE`: SPI トランザクション中のウェイトステートのチェックを有効にします。ほとんどの TPM 2.0 チップで必要で、コマンドによって通常 0 から 2 ウェイトサイクルのみが必要です。ウェイトステートが発生しないことを保証しているのは Infineon の TPM のみです。
* `WOLFTPM_ADV_IO`: TIS レジスタと読み書きフラグを含む拡張 IO コールバックモードを有効にします。I2C には必須ですが、SPI でも使用できます。
* `WOLFTPM_DEBUG_IO`: IO のログ出力を有効にします (サンプル HAL を使用している場合)。
* `WOLFTPM_HAL_RESET`: サンプル HAL における TPM ハードウェアリセット (nRST) 制御を有効にするオプションです (`--enable-hal-reset`)。Linux では、`TPM2_IoCb_Reset(&dev->ctx, userCtx)` が GPIO キャラクタデバイス (raw GPIO v2 uAPI、libgpiod 不要) を通じて nRST (アクティブロー) にパルスを出力します。

## TPM リセット (nRST) HAL マクロ

これらは `WOLFTPM_HAL_RESET` が設定されている場合に適用されます。

* `WOLFTPM_RESET_GPIOCHIP`: GPIO キャラクタデバイス。デフォルト: `/dev/gpiochip0`。
* `WOLFTPM_RESET_LINE`: nRST に接続されている GPIO ライン。デフォルト: ST33 は `24` (GPIO24、Pi ピン 18)、Nuvoton は `4` (GPIO4)。`--enable-hal-reset=<line>` でも設定できます。
* `WOLFTPM_RESET_HOLD_US` と `WOLFTPM_RESET_SETTLE_US`: リセット保持時間とリセット後の安定待ち時間 (マイクロ秒単位)。デフォルト: `300000` と `1000000`。

## 追加のコンパイラマクロ

* `TPM2_SPI_DEV_PATH`: Linux IO コールバックがオープンするデバイス文字列。デフォルト: `"/dev/spidev0."`。
* `TPM2_SPI_DEV_CS`: 使用するチップセレクト番号の文字列。デフォルト: `"0"`。

これらは configure 時に設定できます。

```sh
./configure CPPFLAGS="-DTPM2_SPI_DEV_PATH=\"/dev/spidev0.\" -DTPM2_SPI_DEV_CS=\"0\""
```

自動検出では、検索するデバイスパスとして `TPM2_SPI_DEV_PATH[0..4]` を使用します。

## 関連項目

* [サポート対象ハードウェア](supported-hardware.md)
* [TPM 2.0 概要](tpm2-overview.md)
