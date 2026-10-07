# ビルドオプション

このページでは、wolfTPM のビルド方法を制御する configure オプションとプリプロセッサ定義を一覧にしています。以下のブロックは、プロジェクトの README から抜粋した参照リストです。configure スイッチごとに、対応するマクロがある場合はそのマクロを示しています。

## ビルドオプションと定義


```text
--enable-debug          デバッグコードを追加し最適化を無効にする (yes|no|verbose|io) - DEBUG_WOLFTPM, WOLFTPM_DEBUG_VERBOSE, WOLFTPM_DEBUG_IO
                        警告: WOLFTPM_DEBUG_SECRETS は手動で定義します (既定では有効ではなく、configure からも
                        指定できません)。定義すると、認証値、セッション鍵、バインド鍵、HMAC 鍵、階層の認証、
                        暗号化シークレットなどの機密情報も出力されます。
                        開発者のデバッグ専用です。本番ビルドや、標準出力を永続ストレージに記録するデバイスでは
                        絶対に有効にしないでください。
--enable-examples       サンプルを有効にする (既定: 有効)
--enable-wrapper        ラッパーコードを有効にする (既定: 有効) - WOLFTPM2_NO_WRAPPER
--enable-wolfcrypt      RNG、認証セッション、パラメータ暗号化用の wolfCrypt フックを有効にする (既定: 有効) - WOLFTPM2_NO_WOLFCRYPT
--enable-advio          拡張 IO を有効にする (既定: 無効) - WOLFTPM_ADV_IO
--enable-spi            SPI ハードウェアビルドであることを示す指定です。--enable-i2c を指定しない場合、SPI が既定のトランスポートです。
                        このフラグはコンパイル時マクロを追加せず、自動有効化される swTPM/fwTPM の既定動作を無効にします。(既定: 未設定)
--enable-i2c            I2C TPM サポートを有効にする (既定: 無効、advio が必要) - WOLFTPM_I2C
--enable-mmio           組み込みの MMIO コールバックを有効にする (既定: 無効) - WOLFTPM_MMIO
--enable-wolfhal        wolfHAL の IO コールバックを有効にする (既定: 無効) - WOLFTPM_WOLFHAL
                        wolfHAL のヘッダーと、アプリケーションが用意する board.h が必要です。
                        必要な BOARD_* 定義については hal/README.md を参照してください。
--enable-checkwaitstate TIS / SPI のウェイトステート確認サポートを有効にする (既定: チップに依存) - WOLFTPM_CHECK_WAIT_STATE
--enable-smallstack     スタック使用量を削減するオプションを有効にする
--enable-tislock        プロセス間の並行アクセスに対して SPI デバイスへのアクセスを排他制御するため、Linux の名前付きセマフォを有効にする - WOLFTPM_TIS_LOCK
--enable-firmware       Infineon SLB9672/SLB9673 および ST ST33 のファームウェアアップグレードサポートを有効にする (既定: 無効) - WOLFTPM_FIRMWARE_UPGRADE

--enable-autodetect     実行時モジュール検出を有効にする (既定: モジュール未指定の場合は有効) - WOLFTPM_AUTODETECT
                        Linux では、実行時に /dev/tpmrm0 または /dev/tpm0 も自動検出し、
                        カーネルドライバーが利用できない場合は SPI にフォールバックします。
--enable-infineon       Infineon SLB9670/SLB9672/SLB9673 TPM サポートを有効にする (既定: 無効) - WOLFTPM_SLB9670 / WOLFTPM_SLB9672
--enable-st             ST ST33 サポートを有効にする (既定: 無効) - WOLFTPM_ST33
--enable-microchip      Microchip ATTPM20 サポートを有効にする (既定: 無効) - WOLFTPM_MICROCHIP
--enable-nuvoton        Nuvoton NPCT65x/NPCT75x サポートを有効にする (既定: 無効) - WOLFTPM_NUVOTON
--enable-nations        Nations Technology NS350 サポートを有効にする (既定: 無効) - WOLFTPM_NATIONS
--enable-sealsq         SealSQ QVault ポスト量子 TPM サポートを有効にする (既定: 無効) - WOLFTPM_SEALSQ

--enable-devtpm         /dev/tpmX 用の Linux カーネルドライバーを使用する (既定: 無効) - WOLFTPM_LINUX_DEV
                        注: autodetect (既定) では、Linux でこの指定は不要になりました。
                        SPI より先にカーネルドライバーが自動的に試行されます。
--enable-swtpm          SWTPM の TCP プロトコルを使用する。シミュレーター用。(既定: Linux x86_64/aarch64 では有効、
                        それ以外、または次のいずれかでハードウェア経路を選択した場合は無効
                        --enable-spi/--enable-i2c/--enable-mmio/--enable-nuvoton/--enable-nations/
                        --enable-infineon/--enable-st/--enable-microchip/--enable-devtpm/--enable-autodetect) - WOLFTPM_SWTPM
--enable-swtpm=uart     UART シリアル経由の SWTPM プロトコルを使用する。組み込みターゲット
                        (例: STM32H5) 上の fwTPM で使用します。TCP ソケットの代わりに
                        termios のシリアル I/O を使用します。 - WOLFTPM_SWTPM + WOLFTPM_SWTPM_UART
--enable-fwtpm          ファームウェア TPM (fwTPM) サーバーを有効にする。既定の動作は --enable-swtpm と同じ
                        (Linux x86_64/aarch64 では自動的に有効、ハードウェア経路を選択した場合は
                        自動的に無効)。 - WOLFTPM_FWTPM_SERVER
--enable-winapi         Windows TBS API を使用する。(既定: 無効) - WOLFTPM_WINAPI

WOLFTPM_USE_SYMMETRIC   TLS サンプル向けに、対称 AES/ハッシュ/HMAC のサポートを有効にします。
WOLFTPM2_USE_SW_ECDHE   TLS サンプルで、ECC 一時鍵の生成と共有シークレットの導出に TPM を使用しないようにします。
WOLFTPM2_ECC_DEFAULT_CURVE  P256 を要求するラッパーの鍵テンプレート (SRK/AIK/一般的な ECC) の既定 ECC カーブ。既定値は TPM_ECC_NIST_P256 で、ECC_MIN_KEY_SZ を満たす有効な最小のカーブになる場合もあります。例: -DWOLFTPM2_ECC_DEFAULT_CURVE=TPM_ECC_NIST_P384 で上書きできます。
TLS_BENCH_MODE          TLS ベンチマークモードを有効にします。
NO_TPM_BENCH            TPM ベンチマークのサンプルを無効にします。
WOLFTPM_MAX_RETRIES     TPM が TPM_RC_RETRY を返したとき (一時的なビジー状態。例: 外部でプロビジョニングされた noDA でない AIK/SUDI 鍵の初回認証使用時に daUsed フラグを永続化する場合) に、コマンドを透過的に再送する既定の回数。既定では無効 (0) です。実行時に TPM2_SetCommandRetries() を呼ぶか、ビルド時に -DWOLFTPM_MAX_RETRIES=N を指定して有効にします。wolfTPM 自身の鍵テンプレートは noDA を設定するため、これが発生することはありません。
WOLFTPM_NO_RETRY        TPM_RC_RETRY の自動再送処理を完全にコンパイル対象から除外します。TPM_RC_RETRY は呼び出し元に返され、手動で処理する必要があります。
WOLFTPM_LOCALITY_DEFAULT  起動時に要求する既定の TIS ロカリティ (既定 0)。SPI/メモリマップドおよび swtpm トランスポートでは、wolfTPM2_SetLocality() により実行時に上書きできます。I2C HAL はロカリティ 0 のみをアドレス指定します (TIS ロカリティはアドレスのビット 12 以上に格納されますが、8 ビットの I2C レジスタアドレスではこれを保持できません)。そのため、I2C で 0 以外のロカリティを wolfTPM2_SetLocality() で指定すると、黙ってロカリティ 0 で動作するのではなく NOT_COMPILED_IN が返されます。
WOLFTPM_TIS_RESET_STALE_LOCALITY  起動時に、他のアクティブなロカリティを解放して既定のロカリティを取得できるようにします。以前のセッションがロカリティ 0 に戻らなかったために発生した停止状態から復旧します。既定ではオフです。シングルマスターのバスでのみ使用してください。共有バスでは、他のマスターが保持しているロカリティを解除してしまう可能性があります (または、nRST リセット HAL を使用して復旧します)。
WOLFTPM_LOCALITY_TIMEOUT_TRIES  実行時にロカリティを要求する際のポーリング試行回数 (既定 1000)。取得できないロカリティを早期に失敗させるため、小さい値に保たれています。
WOLFTPM_RESET_LINE      オプションのリセット HAL 用の nRST GPIO ライン番号。--enable-hal-reset=LINE で設定し、TPM2_IoCb_Reset() で駆動します (hal/README.md を参照)。
```

!!! note
    Raspberry Pi で I2C をサポートするには、先に I2C を有効にする必要がある場合があります。

    1. `/boot/config.txt` を編集します (例: `sudo vim /boot/config.txt`)。
    2. `dtparam=i2c_arm=on` のコメントを外します。
    3. `sudo reboot` で再起動します。

## configure オプションの完全なリファレンス

wolfTPM のソースツリーにある `configure.ac` が、configure オプションの正式かつ網羅的な一覧です。マクロごとの網羅的なリファレンスは、本マニュアルの今後の改訂で拡充される予定です。現在存在するオプションのファミリーは次のとおりです。

| ファミリー | オプションとマクロ |
| --- | --- |
| デバッグ | `--enable-debug`, `DEBUG_WOLFTPM`, `WOLFTPM_DEBUG_VERBOSE`, `WOLFTPM_DEBUG_IO` |
| ラッパーと wolfCrypt | `--enable-wrapper` (`WOLFTPM2_NO_WRAPPER`), `--enable-wolfcrypt` (`WOLFTPM2_NO_WOLFCRYPT`) |
| IO レイヤー | `--enable-advio`, `--enable-i2c`, `--enable-mmio`, `--enable-wolfhal`, `--enable-spi` |
| タイミングとロック | `--enable-checkwaitstate`, `--enable-tislock` |
| ファームウェアアップグレード | `--enable-firmware` (`WOLFTPM_FIRMWARE_UPGRADE`) |
| モジュール検出 | `--enable-autodetect` (`WOLFTPM_AUTODETECT`) |
| ベンダー | `--enable-infineon` (SLB9670, SLB9672, SLB9673), `--enable-st` (ST33), `--enable-microchip`, `--enable-nuvoton`, `--enable-nations`, `--enable-sealsq` |
| オペレーティングシステムのトランスポート | `--enable-devtpm` (`WOLFTPM_LINUX_DEV`), `--enable-winapi` (`WOLFTPM_WINAPI`) |
| シミュレーターとファームウェア TPM | `--enable-swtpm`, `--enable-swtpm=uart`, `--enable-fwtpm` (`WOLFTPM_FWTPM_SERVER`) |
| 実行時の動作 | `WOLFTPM_MAX_RETRIES`, `WOLFTPM_NO_RETRY`, `WOLFTPM_LOCALITY_DEFAULT`, `WOLFTPM_TIS_RESET_STALE_LOCALITY`, `WOLFTPM_LOCALITY_TIMEOUT_TRIES`, `WOLFTPM_RESET_LINE`, `WOLFTPM2_ECC_DEFAULT_CURVE` |

## 関連項目

- [wolfTPM のビルド](building.md)
- [システムインターフェース](system-interfaces.md)
- [対応ハードウェア](supported-hardware.md)
- [はじめに](getting-started.md)
