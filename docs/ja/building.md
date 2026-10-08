# wolfTPM のビルド

wolfTPM は wolfSSL (wolfCrypt) の上に構築されており、autotools、CMake、または `user_settings.h` ファイルを使用したベアメタルプロジェクトへの直接組み込みでビルドできます。このページでは各ビルド方法を説明します。ベンダーごとのビルド手順は[対応ハードウェア](supported-hardware.md)ページに、configure スイッチの完全な一覧は[ビルドオプション](build-options.md)ページに記載されています。

## wolfSSL のビルド

最初に wolfSSL をビルドしてインストールする必要があります。wolfSSL は[ダウンロードページ](https://wolfssl.com/download/)から入手するか、GitHub からクローンできます。

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm
make
sudo make install
sudo ldconfig
```

`autogen.sh` には automake と libtool が必要です: `sudo apt-get install automake libtool`。

`--enable-wolftpm` オプションは、次のオプションを指定した場合と同等です。

```bash
./configure --enable-certgen --enable-certreq --enable-certext \
    --enable-pkcs7 --enable-cryptocb --enable-aescfb
```

## 別の wolfSSL ディレクトリを使用する

既定以外の場所にインストールした wolfSSL に対して wolfTPM をビルドするには、wolfSSL を任意のプレフィックスにインストールし、`--with-wolfcrypt` で wolfTPM にその場所を指定します。

```bash
# cd /your-wolfssl-repo
./autogen.sh # as necessary
./configure --prefix=~/workspace/my_wolfssl_bin --enable-all
make install

# then for some other library such as wolfTPM:

# cd /your-wolftpm-repo
./configure --enable-swtpm --with-wolfcrypt=~/workspace/my_wolfssl_bin
```

## autotools でのビルド

wolfSSL をインストールしたら、[ダウンロードページ](https://wolfssl.com/download/)から wolfTPM を入手するか GitHub からクローンして、ビルドします。

```bash
git clone https://github.com/wolfSSL/wolfTPM.git
cd wolfTPM
./autogen.sh
./configure
make
```

必要なオプションを `./configure` に追加してください。たとえば、`--enable-devtpm` は Linux カーネルの TPM デバイスを使用し、`--enable-swtpm` は TPM シミュレータを使用します。オプションの一覧は[ビルドオプション](build-options.md)を、各 TPM モジュールに必要なオプションは[対応ハードウェア](supported-hardware.md)を参照してください。

Linux の x86_64 と aarch64 では、オプションなしの `./configure` を実行すると、ハードウェアなしで `make check` が動作するように、ソフトウェア TPM バックエンドが自動的に有効になります。[システムインターフェース](system-interfaces.md)を参照してください。

## CMake でのビルド

CMake は、CMake サポートがインストールされている場合の Visual Studio を含め、多くの環境でのコンパイルをサポートします。以下のコマンドは `Developer Command Prompt` で実行できます。

```bash
mkdir build
cd build
# to use installed wolfSSL location (library and headers)
cmake .. -DWITH_WOLFSSL=/prefix/to/wolfssl/install/
# OR to use a wolfSSL source tree
cmake .. -DWITH_WOLFSSL_TREE=/path/to/wolfssl/
# build
cmake --build .
```

wolfSSL がすでにインストールされている (ライブラリとヘッダー) 場合は `-DWITH_WOLFSSL=` を、wolfSSL のソースツリーに対してビルドする場合は `-DWITH_WOLFSSL_TREE=` を使用します。

## ベアメタルビルド

wolfTPM は、オペレーティングシステムが存在しないベアメタルの組み込み環境向けにビルドできます。この方法では、autotools や CMake を使用せず、wolfTPM のソースファイルをプロジェクトに直接コンパイルします。ARM Cortex-M、RISC-V、UltraScale+/Versal、Microblaze などのマイクロコントローラでよく使われます。

### 前提条件

- wolfCrypt ライブラリのソースコード
- wolfTPM ライブラリのソースコード
- SPI (または I2C) で接続された TPM 2.0 モジュール

### 手順 1: プリプロセッサマクロを定義する

次のプリプロセッサマクロを、プロジェクトのビルド設定またはコンパイラのコマンドラインに追加します。

```
WOLFTPM_USER_SETTINGS
WOLFSSL_USER_SETTINGS
```

これらのマクロは、autoconf が生成する `options.h` ファイルの代わりに `user_settings.h` ファイルを使用するよう、wolfTPM と wolfSSL に指示します。

### 手順 2: user_settings.h ファイルを作成する

wolfSSL と wolfTPM の両方のビルド設定オプションを記述した `user_settings.h` ファイルをプロジェクトに作成します。参考用の設定ファイルが wolfSSL リポジトリにあります: [examples/configs/user_settings_wolftpm.h](https://github.com/wolfSSL/wolfssl/blob/master/examples/configs/user_settings_wolftpm.h)。

wolfTPM 向けの `user_settings.h` の例:

```c
/* System */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED
#define WOLFCRYPT_ONLY
#define SIZEOF_LONG_LONG 8

/* Platform - bare metal */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_ERROR_STRINGS
#define NO_SIG_WRAPPER

/* wolfTPM required features */
#define WOLF_CRYPTO_CB
#define WOLFSSL_PUBLIC_MP
#define WOLFSSL_AES_CFB
#define HAVE_AES_DECRYPT

/* ECC options */
#define HAVE_ECC
#define ECC_TIMING_RESISTANT

/* RSA options */
#undef NO_RSA
#define WOLFSSL_KEY_GEN
#define WC_RSA_BLINDING

/* Big math library */
#define WOLFSSL_SP_MATH_ALL /* sp_int.c */
#define WOLFSSL_SP_SMALL
#define SP_INT_BITS 4096
/* #define SP_WORD_SIZE 32 */

/* SHA options: SHA-256 stays enabled, so do not define NO_SHA256 */
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

/* Disable unneeded features to reduce footprint */
#define NO_PKCS8
#define NO_PKCS12
#define NO_PWDBASED
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define NO_MD5
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256
#define NO_DH

/* Other interesting size reduction options */
#if 0
    #define RSA_LOW_MEM
    #define WOLFSSL_AES_SMALL_TABLES
    #define USE_SLOW_SHA
    #define USE_SLOW_SHA256
    #define USE_SLOW_SHA512
    #define NO_AES_192
#endif

/* Custom random seed source - implement your own */
#define HAVE_HASHDRBG
#define CUSTOM_RAND_GENERATE_SEED my_rng_seed
```

!!! warning
    `NO_*` マクロはアルゴリズムを無効にします。wolfTPM のラッパーとセッションには SHA-256 が必要なため、このファイルで `NO_SHA256` を定義してはいけません。

`CUSTOM_RAND_GENERATE_SEED` を使用する場合は、独自の RNG シード関数を実装してください。次の例は、パラメータ暗号化を有効にして TPM からシードを取得します。

```c
int my_rng_seed(byte* seed, word32 sz)
{
    int rc;

    /* enable parameter encryption for the RNG request */
    rc = wolfTPM2_SetAuthSession(&wolftpm_dev, 0, &wolftpm_session,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc == 0) {
        rc = wolfTPM2_GetRandom(&wolftpm_dev, seed, sz);
    }
    wolfTPM2_UnsetAuthSession(&wolftpm_dev, 0, &wolftpm_session);
    return rc;
}
```

### 手順 3: インクルードパスを設定する

次のディレクトリをプロジェクトのインクルードパスに追加します。

1. wolfSSL のルートディレクトリ (例: `/path/to/wolfssl`)
2. wolfTPM のルートディレクトリ (例: `/path/to/wolftpm`)
3. `user_settings.h` を置いているディレクトリ

コンパイラフラグの例:

```
-I/path/to/wolfssl
-I/path/to/wolftpm
-I/path/to/your/project/include
```

### 手順 4: ソースファイルを追加する

wolfSSL と wolfTPM から必要なソースファイルをプロジェクトに追加します。

wolfCrypt のソースファイル (wolfTPM に最低限必要なもの):

```
wolfssl/wolfcrypt/src/aes.c
wolfssl/wolfcrypt/src/asn.c
wolfssl/wolfcrypt/src/cryptocb.c
wolfssl/wolfcrypt/src/ecc.c
wolfssl/wolfcrypt/src/hash.c
wolfssl/wolfcrypt/src/hmac.c
wolfssl/wolfcrypt/src/random.c
wolfssl/wolfcrypt/src/rsa.c
wolfssl/wolfcrypt/src/sha.c
wolfssl/wolfcrypt/src/sha256.c
wolfssl/wolfcrypt/src/sha512.c
wolfssl/wolfcrypt/src/sp_int.c
wolfssl/wolfcrypt/src/wc_port.c
wolfssl/wolfcrypt/src/wolfmath.c
```

wolfTPM のソースファイル:

```
wolftpm/src/tpm2.c
wolftpm/src/tpm2_util.c
wolftpm/src/tpm2_packet.c
wolftpm/src/tpm2_tis.c
wolftpm/src/tpm2_wrap.c
wolftpm/src/tpm2_asn.c
wolftpm/src/tpm2_crypto.c
wolftpm/src/tpm2_param_enc.c
wolftpm/src/tpm2_cryptocb.c
wolftpm/src/tpm2_linux.c
```

このリストは `src/include.am` の `src_libwolftpm_la_SOURCES` に対応します。`tpm2_swtpm.c`、`tpm2_winapi.c`、`tpm2_spdm.c` は、それぞれのオプションビルドでのみ必要です。HAL のソース (`hal/tpm_io*.c` のいずれか、後述) は別途追加します。

### 手順 5: SPI HAL コールバックを実装する

wolfTPM が TPM モジュールと通信するには、SPI の送受信コールバックが 1 つ必要です。お使いのハードウェアプラットフォーム向けに実装してください。参考実装は wolfTPM リポジトリの `hal/` ディレクトリにあります。

- [hal/tpm_io_xilinx.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_xilinx.c): Xilinx Microblaze 向け
- [hal/tpm_io_st.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_st.c): STM32 向け
- [hal/tpm_io_infineon.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_infineon.c): Infineon Tricore 向け
- [hal/tpm_io_microchip.c](https://github.com/wolfSSL/wolfTPM/blob/master/hal/tpm_io_microchip.c): Microchip 向け

#### 標準 I/O コールバック

標準の SPI コールバックのシグネチャは次のとおりです。

```c
typedef int (*TPM2HalIoCb)(
    TPM2_CTX* ctx,
    const byte* txBuf, byte* rxBuf,
    word16 xferSz,
    void* userCtx
);
```

実装例:

```c
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_tis.h>

int TPM2_IoCb(TPM2_CTX* ctx,
    const byte* txBuf, byte* rxBuf, word16 xferSz,
    void* userCtx)
{
    int ret = TPM_RC_FAILURE;

    /* TODO: Assert SPI chip select */
    spi_cs_assert();

    /* Perform SPI transfer: send txBuf and receive into rxBuf */
    if (spi_transfer(txBuf, rxBuf, xferSz) == 0) {
        ret = TPM_RC_SUCCESS;
    }

    /* TODO: De-assert SPI chip select */
    spi_cs_deassert();

    (void)ctx;
    (void)userCtx;

    return ret;
}
```

#### 拡張 I/O コールバック

より細かい制御が必要なプラットフォームでは、`WOLFTPM_ADV_IO` を有効にして拡張コールバックを使用します。

```c
typedef int (*TPM2HalIoCb)(
    TPM2_CTX* ctx,
    INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz,
    void* userCtx
);
```

これにより、レジスタアドレスと読み取り/書き込みの方向にアクセスできるため、読み取りと書き込みの操作を分けて扱う必要があるプラットフォームで利用できます。

### 手順 6: wolfTPM を初期化して使用する

セットアップが完了したら、wolfTPM を初期化して TPM との通信を開始します。

```c
#include <wolftpm/tpm2_wrap.h>

int main(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Initialize wolfTPM */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    if (rc != TPM_RC_SUCCESS) {
        /* Handle error */
        return rc;
    }

    /* Get TPM capabilities */
    WOLFTPM2_CAPS caps;
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    if (rc == TPM_RC_SUCCESS) {
        /* Use TPM ... */
    }

    /* Cleanup */
    wolfTPM2_Cleanup(&dev);

    return 0;
}
```

### オプションのビルド構成

リソースの限られた環境でメモリフットプリントを削減するには、`user_settings.h` で次のオプションを検討してください。

```c
/* Reduce stack usage */
#define WOLFTPM_SMALL_STACK

/* Disable wrapper layer if using native API only */
#define WOLFTPM2_NO_WRAPPER

/* Use smaller RSA key sizes only */
#define MAX_RSA_BITS 2048
```

コンパイル時に TPM モジュールの種類が分かっている場合は、それを選択します。複数ではなく、モジュールのバリアントを 1 つだけ選択してください。

```c
/* For Infineon, pick exactly one of these */
#define WOLFTPM_SLB9670
/* #define WOLFTPM_SLB9672 */
/* #define WOLFTPM_SLB9673 */

/* For ST ST33 */
#define WOLFTPM_ST33

/* For Nuvoton */
#define WOLFTPM_NUVOTON

/* For Microchip ATTPM20 */
#define WOLFTPM_MICROCHIP
```

モジュールを指定しない場合、wolfTPM は `WOLFTPM_AUTODETECT` (既定) を使用して、実行時に自動検出を試みます。

SPI ではなく I2C で接続された TPM モジュールの場合:

```c
#define WOLFTPM_I2C
#define WOLFTPM_ADV_IO
```

I2C 通信には、拡張 I/O コールバックを実装する必要があります。

### 暗号鍵の保管

ベアメタル環境では、TPM がメインプロセッサのメモリから分離された、暗号鍵のためのセキュアな保管場所を提供します。鍵素材が平文の形で TPM の外に出ることはありません。

- `TPM2_CreatePrimary` で作成した鍵は TPM 内に存在し、ハンドルが返されます。
- `TPM2_Create` で作成した鍵は暗号化されたブロブとして返され、不揮発性メモリに保存して `TPM2_Load` で再ロードできます。
- `TPM2_EvictControl` を使用すると、鍵を TPM の NVRAM に永続的に保存できます。

これにより、メインプロセッサのメモリが侵害された場合でも、暗号鍵は保護されたままになります。

### トラブルシューティング

SPI 通信の問題:

1. SPI のクロック極性と位相を確認します (TPM では通常 CPOL=0、CPHA=0)。
2. SPI クロック速度を確認します。低速 (1 ～ 10 MHz) から始めて、徐々に上げてください。
3. 送受信の全期間にわたって、チップセレクトがローにアサートされていることを確認します。
4. 一部の TPM では、SPI 操作中にウェイトステートが必要です。これは、レスポンスの準備完了を示す MSB が立つまで追加のバイトを読み取ることを意味します (`WOLFTPM_CHECK_WAIT_STATE` で有効化)。
5. デバッグ出力は、`DEBUG_WOLFTPM` (一般)、`WOLFTPM_DEBUG_VERBOSE` (詳細)、`WOLFTPM_DEBUG_IO` (SPI と I2C のトランザクション) で有効にできます。

ビルドエラー:

1. `WOLFSSL_USER_SETTINGS` と `WOLFTPM_USER_SETTINGS` が定義されていることを確認します。
2. インクルードパスが正しいことを確認します。
3. 必要なソースファイルがすべてビルドに含まれていることを確認します。

## 関連項目

- [はじめに](getting-started.md)
- [ビルドオプション](build-options.md)
- [対応ハードウェア](supported-hardware.md)
- [システムインターフェース](system-interfaces.md)
