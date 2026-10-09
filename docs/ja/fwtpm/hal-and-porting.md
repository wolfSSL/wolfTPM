# HAL と移植

fwTPM はハードウェア抽象化レイヤー (HAL) を提供しており、コアロジックを変更せずに組み込みターゲットへ移植できます。トランスポート用の IO HAL、永続ストレージ用の NV HAL、およびオプションのクロック HAL があります。複数のボード向けの完全なリファレンス移植は、[wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples) リポジトリにあります。

## IO HAL (トランスポート)

IO HAL は、fwTPM サーバーとそのクライアント間のトランスポートを抽象化します。デフォルトの実装は TCP ソケット (SWTPM プロトコル) を使用します。組み込みターゲットでは、SPI、I2C、UART、または共有メモリのコールバックに置き換えます。

**コールバック構造体** (`fwtpm.h` で `FWTPM_IO_HAL` として定義):

| コールバック | シグネチャ | 説明 |
|----------|-----------|-------------|
| `send` | `int (*)(void* ctx, const void* buf, int sz)` | クライアントへデータを送信 |
| `recv` | `int (*)(void* ctx, void* buf, int sz)` | クライアントからデータを受信 |
| `wait` | `int (*)(void* ctx)` | データまたは接続を待機。ビットマスクを返す: `0x01`=コマンドデータ、`0x02`=プラットフォームデータ、`0x04`=新しいコマンド接続、`0x08`=新しいプラットフォーム接続 |
| `accept` | `int (*)(void* ctx, int type)` | 新しい接続を受け入れる (type: 0=コマンド、1=プラットフォーム) |
| `close_conn` | `void (*)(void* ctx, int type)` | 接続を閉じる (type: 0=コマンド、1=プラットフォーム) |
| `ctx` | `void*` | ユーザーコンテキストポインタ |

**登録:**

```c
FWTPM_IO_HAL myHal;
myHal.send = my_send;
myHal.recv = my_recv;
myHal.wait = my_wait;
myHal.accept = my_accept;
myHal.close_conn = my_close;
myHal.ctx = &myTransportCtx;

FWTPM_IO_SetHAL(&ctx, &myHal);
```

## NV HAL (永続ストレージ)

NV HAL は永続ストレージを抽象化します。デフォルトの実装はローカルファイル (`fwtpm_nv.bin`) を使用します。組み込みターゲットでは、フラッシュ、EEPROM、その他の不揮発性ストレージのコールバックに置き換えます。

**コールバック構造体** (`fwtpm.h` で `FWTPM_NV_HAL` として定義):

| コールバック | シグネチャ | 説明 |
|----------|-----------|-------------|
| `read` | `int (*)(void* ctx, word32 offset, byte* buf, word32 size)` | オフセットを指定して NV から読み取り |
| `write` | `int (*)(void* ctx, word32 offset, const byte* buf, word32 size)` | オフセットを指定して NV へ書き込み |
| `erase` | `fwtpm.h` を参照 | NV 領域を消去 (フラッシュの移植およびコンパクションで使用) |
| `ctx` | `void*` | ユーザーコンテキストポインタ |
| `maxSize` | `word32` | NV 領域のサイズ (バイト) |
| `appendOnly`, `writeAlign` | フィールド | アペンドオンリーモードとプログラム粒度のサイズ (後述) |
| `get_integrity_key` | コールバック | ジャーナルの認証に使用するデバイスシークレットを提供 |

**登録:**

```c
FWTPM_NV_HAL myNvHal;
myNvHal.read = my_flash_read;
myNvHal.write = my_flash_write;
myNvHal.ctx = &myFlashCtx;

FWTPM_NV_SetHAL(&ctx, &myNvHal);
```

HAL は `FWTPM_Init()` の前に登録してください。

### 組み込み移植向けの NV ストレージ HAL

NV アクセスは `FWTPM_NV_HAL` (`read`、`write`、`erase`、`ctx`、`maxSize`、`get_integrity_key`) を通じて行われます。デフォルトのバックエンドはファイルです。組み込みの移植では独自の HAL を用意し、`FWTPM_Init()` の前に登録します。

ジャーナルはログ構造です。バイトアドレス指定可能なバックエンド (デフォルトのファイル) では、バイト単位のオフセットに TLV エントリを書き込み、ヘッダーをその場で書き換え、追記のたびに末尾の整合性 MAC を書き換えます。内蔵フラッシュと NOR はライトワンスであり、プログラム粒度にアラインされているため、その場での書き換えには対応できません。

そのようなデバイスでは、`--enable-fwtpm-nv-appendonly` (`-DWOLFTPM_FWTPM_NV_APPEND_ONLY`、CMake では `WOLFTPM_FWTPM_NV_APPEND_ONLY=yes`) を指定してビルドし、HAL に `appendOnly` と `writeAlign` を設定します。ジャーナルはアペンドオンリーモードで動作します。

- ヘッダーはコンパクション時にのみ書き込まれます。
- `writePos` はロード時のスキャンによって導出されます。
- 各コミットは、`writeAlign` までパディングされた MAC チェックポイントエントリを追記することで封印されます。

既存の `read`、`write`、`erase` の HAL が統合ポイントです。別途アダプタはありません。

```c
/* Native flash HAL. In append-only mode the journal only ever calls write()
 * with writeAlign-aligned, forward, into-erased bytes, so write() is a simple
 * flash program; erase() erases the region (sector loop); read() reads raw. */
FWTPM_NV_HAL hal;
XMEMSET(&hal, 0, sizeof(hal));
hal.read = myRead; hal.write = myProgram; hal.erase = myErase;
hal.ctx = myCtx; hal.maxSize = NV_SIZE;
hal.appendOnly = 1;
hal.writeAlign = PROG_SIZE;            /* flash word size, e.g. 16 (STM32H5) */
hal.get_integrity_key = myDeviceSecret;/* recommended on flash */
FWTPM_NV_SetHAL(&ctx, &hal);           /* before FWTPM_Init() */
```

アペンドオンリーモードでは、ジャーナルは保留中のプログラム粒度を内部でバッファリングし、満たされたアライン済みの粒度を `write()` 経由でフラッシュします。プログラム済みのセルが書き換えられることはなく、セクタ全体が消去されるのはコンパクション時のみです。そのため、ヘッダーセクタは追記のたびに消去されることがなく、(たとえば電源断による) 最後のコミットの中断は次回のロード時に無視され、それ以前にコミットされたすべての状態は保持されます。

フラッシュでは `get_integrity_key` コールバックを強く推奨します。これにより MAC チェックポイントがジャーナルを認証し、中断または改ざんされた末尾を拒否できます。`writeAlign <= 1` を設定するとバッファリングなしが選択され、バイト書き込み可能な NV (EEPROM または FRAM) でも単純な `write()` で動作します。

!!! warning
    コンパクションでは、書き直す前に領域全体を依然として消去するため、コンパクション自体の最中に電源が失われる場合は脆弱な期間が残ります。将来、2 領域のピンポン方式のレイアウトを導入すれば、この問題を解消できます。

## クロック HAL

クロック HAL はオプションです。起動からの経過ミリ秒を返す `get_ms()` を提供します。`FWTPM_Init()` の前に `FWTPM_Clock_SetHAL()` で登録してください。クロック HAL を登録すると、ディクショナリアタック保護が時間の経過とともに自己回復します ([概要](overview.md)を参照)。

## 移植の例

SPI トランスポートと SPI フラッシュの NV を使用するベアメタルの組み込みターゲットの例です。

```c
FWTPM_CTX ctx;
XMEMSET(&ctx, 0, sizeof(ctx));

/* Set custom NV storage before FWTPM_Init, which loads NV state through it */
FWTPM_NV_HAL nvHal = {
    .read = spi_flash_read,
    .write = spi_flash_write,
    .ctx = &flashHandle
};
FWTPM_NV_SetHAL(&ctx, &nvHal);

FWTPM_Init(&ctx);

/* Set custom IO transport after FWTPM_Init, which does not preserve the IO HAL */
FWTPM_IO_HAL ioHal = {
    .send = spi_slave_send,
    .recv = spi_slave_recv,
    .wait = spi_slave_poll,
    .accept = NULL,         /* not connection-oriented */
    .close_conn = NULL,
    .ctx = &spiHandle
};
FWTPM_IO_SetHAL(&ctx, &ioHal);

/* Initialize IO and run */
FWTPM_IO_Init(&ctx);
FWTPM_IO_ServerLoop(&ctx);  /* blocks */

FWTPM_IO_Cleanup(&ctx);
FWTPM_Cleanup(&ctx);
```

## 利用可能な移植

| 移植先 | リポジトリ | 説明 |
|------|-----------|-------------|
| STM32H5 | [STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) | TrustZone (CMSE) を備えた STM32H5 Cortex-M33。内蔵フラッシュの NV |
| PolarFire SoC | [Microchip/fwtpm-polarfire-miv](https://github.com/wolfSSL/wolftpm-examples/tree/main/Microchip/fwtpm-polarfire-miv) | MPFS250T。U54 RISC-V ハート上の M モードでベアメタル動作する fwTPM (Linux と並行する HSS AMP)、共有 L2-LIM メモリ上の TIS |
| Zynq UltraScale+ ZCU102 | [Xilinx/fwtpm-zcu102-r5](https://github.com/wolfSSL/wolftpm-examples/tree/main/Xilinx/fwtpm-zcu102-r5) | ZynqMP MPSoC。ロックステップの Cortex-R5 RPU ペア上でベアメタル動作する fwTPM、A53 (PetaLinux) 上の OpenAMP RPMsg クライアント。揮発性の DDR NV または永続的な QSPI |

## 移植ガイド

新しいプラットフォームを追加するには、次の HAL コールバックを実装します。

1. **NV ストレージ HAL** (`FWTPM_NV_HAL`): 永続的なフラッシュストレージのための `read()`、`write()`、`erase()`。`FWTPM_Init()` の前に `FWTPM_NV_SetHAL()` で登録します。

    NV ジャーナルはログ構造です。バイトアドレス指定可能なバックエンドでは、バイト単位のオフセットに書き込み、追記のたびにヘッダーと末尾の整合性 MAC をその場で書き換えます。内蔵フラッシュと NOR はライトワンスであり、プログラム粒度にアラインされているため、その場での書き換えには対応できません。そのようなデバイスでは、`--enable-fwtpm-nv-appendonly` を指定してビルドし、`FWTPM_NV_SetHAL()` の前に `hal.appendOnly = 1` と `hal.writeAlign = <program size>` (例: STM32H5 では 16) を設定します。

    ジャーナルはその後、ヘッダーをコンパクション時にのみ書き込み、ロード時のスキャンで `writePos` を導出し、プログラム粒度にアラインされた MAC チェックポイントを追記して各コミットを封印し、保留中のプログラム粒度を内部でバッファリングします。`write()` が呼び出されるのは、`writeAlign` にアラインされた、前方へ進む、消去済みの領域へのバイトに対してのみです。したがって、移植側の `write()` はバッファリングや読み出し・修正・書き込みのない単純なフラッシュプログラムで済み、`erase()` は領域を消去し (セクタのループ)、`read()` は生のバイトを読み取ります。プログラム済みのセルが書き換えられることはなく、セクタ全体が消去されるのはコンパクション時のみであるため、追記のたびにヘッダーセクタが摩耗することはなく、最後のコミットが中断しても次回のロード時に無視されます。チェックポイントがジャーナルを認証できるよう、`FWTPM_NV_HAL` に `get_integrity_key` を指定してください。`writeAlign <= 1` を設定すると、EEPROM や FRAM などのバイト書き込み可能な NV に対してバッファリングが無効になります。

2. **クロック HAL** (オプション): 起動からの経過ミリ秒を返す `get_ms()`。`FWTPM_Init()` の前に `FWTPM_Clock_SetHAL()` で登録します。

3. **エントリポイント**: `FWTPM_CTX` をゼロクリアし、HAL を登録して `FWTPM_Init()` を呼び出し、その後 `FWTPM_ProcessCommand()` で TPM コマンドを処理します。

完全なリファレンス実装については、wolftpm-examples の STM32 の移植を参照してください。

## 関連項目

- [概要](overview.md)
- [ビルド](building.md)
- [使用方法](usage.md)
- [ポスト量子サポート](post-quantum.md)
- [SPDM レスポンダ](spdm.md)
