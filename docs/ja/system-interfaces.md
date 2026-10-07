# システムインターフェース

wolfTPM は、SPI や I2C 経由で TPM チップと直接通信するだけでなく、オペレーティングシステムのインターフェースやソフトウェアシミュレーターを通じて TPM にアクセスすることもできます。このページでは、ソフトウェア TPM シミュレーター (SWTPM)、Linux カーネルデバイス (`/dev/tpmX`)、Windows TBS API の 3 つを説明します。1 回のビルドで有効にできるトランスポートは 1 つだけです。

## ソフトウェアシミュレーター (SWTPM)

wolfTPM は、[TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code](https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-4-Supporting-Routines-01.38-code.pdf) のセクション D.3 で定義されたソフトウェア TPM を使用できます。

動作を確認済みのソフトウェア TPM 実装:

* [Official TCG Reference](https://github.com/TrustedComputingGroup/TPM): TCG が管理している仕様のリファレンスコードです。[TCG TPM](#tcg-tpm) を参照してください。
* [IBM (ibmswtpm2) / Ken Goldman](https://github.com/kgoldman/ibmswtpm2): IBM が管理しているリファレンスコードのフォークです (公式の TCG コードと 93% 同一)。[ibmswtpm2](#ibmswtpm2) を参照してください。
* [Microsoft ms-tpm-20-ref](https://github.com/microsoft/ms-tpm-20-ref): Microsoft が管理しているリファレンスコードのフォークです (公式の TCG コードと 100% 同一)。[ms-tpm-20-ref](#ms-tpm-20-ref) を参照してください。
* [libtpms/swtpm by Stefan Berger](https://github.com/stefanberger/swtpm): libtpms のフロントエンドインターフェースを使用します。[swtpm](#swtpm) を参照してください。

ソフトウェア TPM のトランスポートは、既定ではソケット接続です。UART もサポートされています。この実装が使用するのは TPM コマンドインターフェース (通常はポート 2321) のみで、プラットフォームインターフェース (通常はポート 2322) はサポートしません。

### wolfTPM の SWTPM サポート

SWTPM のソケットトランスポートを有効にするには、`--enable-swtpm` を使用します。既定では、すべてのソフトウェア TPM シミュレーターが TCP ポート 2321 を使用します。

```sh
./configure --enable-swtpm
make
```

!!! note
    複数のトランスポートインターフェースを同時に有効にすることはできません。SWTPM のソケットインターフェースを使ってビルドする場合、組み込みの TIS および devtpm (`/dev/tpm0`) インターフェースは利用できません。

ビルドオプション:

* `WOLFTPM_SWTPM`: ソケットトランスポートを使用する (TIS レイヤーなし)
* `TPM2_SWTPM_HOST`: ソケットのホスト (既定は localhost)
* `TPM2_SWTPM_PORT`: ソケットのポート (既定は 2321)

### wolfTPM の SWTPM UART サポート

TCP ソケットの代わりに UART シリアル接続で SWTPM プロトコルを使用するには、`--enable-swtpm=uart` を使用します。これは、STM32H5 上の wolfTPM fwTPM サーバーのように、組み込みターゲットで動作するファームウェア TPM (fwTPM) と通信するためのものです。

```sh
./configure --enable-swtpm=uart
make
```

シリアルデバイスのパスとボーレートは、コンパイル時または実行時に設定できます。

```sh
# Runtime override via environment variable
TPM2_SWTPM_HOST=/dev/ttyACM0 ./examples/wrap/caps
```

ビルドオプション:

* `WOLFTPM_SWTPM_UART`: UART シリアルトランスポートを使用する (`--enable-swtpm=uart` により自動的に設定される)
* `TPM2_SWTPM_HOST`: シリアルデバイスのパス (既定は Linux で `/dev/ttyACM0`、macOS で `/dev/cu.usbmodem`)。実行時には環境変数 `TPM2_SWTPM_HOST` で上書きできます。
* `TPM2_SWTPM_PORT`: ボーレート (既定は 115200)

UART トランスポートは、ソケットトランスポートと同じ mssim プロトコルを使用します。シリアルポートは 8N1 の raw モード、フロー制御なしで構成されます。ソケットトランスポートと同様に、シリアルポートのファイルディスクリプターはコマンド間で開いたままになります (コマンドごとの再接続は行いません)。どちらのトランスポートも、`wolfTPM2_Cleanup` の際に接続を閉じます。ソケットトランスポートでは、送信または受信に失敗した場合にも接続を閉じ、次のコマンドで再接続します。UART トランスポートは、コマンドごとの `TPM_SESSION_END` の書き込みが失敗した場合にのみ接続を閉じます。

#### セキュリティ上の注意: 環境変数による上書き

環境変数 `TPM2_SWTPM_HOST` は、コンパイル時に指定したシリアルデバイスのパスを上書きする開発用の便宜機能です。信頼できないローカルユーザーが TPM クライアントと環境を共有するシステムでは、攻撃者が TPM の I/O を、自身が制御する PTY などの不正なデバイスにリダイレクトできる可能性があります。本番環境や堅牢化した環境では、次のようにしてください。

* プロセス環境で `TPM2_SWTPM_HOST` を未設定にします。
* シリアルパスを固定するため、コンパイル時の既定値 (ビルド時の `-D` マクロとして `TPM2_SWTPM_HOST` を設定) を使用します。

同じ指針は `TPM2_SWTPM_PORT` (ボーレート) にも当てはまります。また、ソケットトランスポートで環境変数を使って TCP ホストをリダイレクトする場合にも当てはまります。

#### 例: STM32H5 上の wolfTPM fwTPM

wolfTPM プロジェクトには、TrustZone をサポートする STM32 Cortex-M33 ターゲット向けのファームウェア TPM サーバーのポートが含まれています。ビルド、書き込み、テストの手順については、[wolftpm-examples/STM32/fwtpm-stm32h5](https://github.com/wolfSSL/wolftpm-examples/tree/main/STM32/fwtpm-stm32h5) を参照してください。

```sh
# Build host client with UART transport
./configure --enable-swtpm=uart
make

# Run examples against STM32 fwTPM (adjust device path as needed)
export TPM2_SWTPM_HOST=/dev/ttyACM0
./examples/wrap/caps
./examples/keygen/keygen -ecc
./examples/seal/seal
```

### SWTPM の使用

#### SWTPM の電源投入と起動

TCG TPM と Microsoft ms-tpm-20-ref の実装では、コマンドインターフェースが有効になる前に、プラットフォームインターフェースで電源投入 (power up) とスタートアップのコマンドを実行する必要があります。必要な電源投入とスタートアップを行うには、次のコマンドを使用します。

```sh
echo -ne "\x00\x00\x00\x01" | nc 127.0.0.1 2322
echo -ne "\x00\x00\x00\x0B" | nc 127.0.0.1 2322
```

#### TCG TPM

```sh
git clone git@github.com:TrustedComputingGroup/TPM.git
cd TPM
cd TPMCmd
./bootstrap
./configure
make
```

`./Simulator/src/tpm2-simulator` で実行し、続いて電源オンとセルフテストを実行します。「SWTPM の電源投入と起動」を参照してください。

#### ibmswtpm2

```sh
git clone https://github.com/kgoldman/ibmswtpm2.git
cd ibmswtpm2/src/
make
```

`./tpm_server` で実行します。

!!! note
    `-rm` スイッチを使うと、キャッシュファイル NVChip を削除できます。または、NVChip ファイルを削除します (`rm NVChip`)。

#### ms-tpm-20-ref

```sh
git clone https://github.com/microsoft/ms-tpm-20-ref
cd ms-tpm-20-ref/TPMCmd
./bootstrap
./configure
make
```

`./Simulator/src/tpm2-simulator` で実行し、続いて電源オンとセルフテストを実行します。「SWTPM の電源投入と起動」を参照してください。

#### swtpm

libtpms をビルドします。

```sh
git clone git@github.com:stefanberger/libtpms.git
cd libtpms
./autogen.sh --with-tpm2 --with-openssl --prefix=/usr
make install
```

swtpm をビルドします。

```sh
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
./autogen.sh
make install
```

macOS では、最初に次を実行します。

```sh
brew install openssl socat
pip3 install cryptography

export LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"
export CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"

# libtpms had to use --prefix=/usr/local
```

swtpm を実行します。

```sh
mkdir -p /tmp/myvtpm
swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322 --server type=tcp,port=2321 --flags not-need-init
```

#### QEMU を使った swtpm

ここでは、QEMU 内で wolfTPM を使用し、Linux カーネルデバイス `/dev/tpmX` を介して通信する方法を示します。[swtpm](https://github.com/stefanberger/swtpm) をインストールまたはビルドしておく必要があります。簡単なビルド方法を以下に示します。[libtpms](https://github.com/stefanberger/libtpms/wiki#compile-and-install-on-linux) と [swtpm](https://github.com/stefanberger/swtpm/wiki#compile-and-install-on-linux) の手順を参照する必要がある場合もあります。

```sh
PREFIX=$PWD/inst
git clone git@github.com:stefanberger/libtpms.git
cd libtpms/
./autogen.sh --with-openssl --with-tpm2 --prefix=$PREFIX && make install
cd ..
git clone git@github.com:stefanberger/swtpm.git
cd swtpm
PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig/ ./autogen.sh --with-openssl --with-tpm2 \
    --prefix=$PREFIX && \
  make install
cd ..
```

基本的な Linux 環境をセットアップします。他のインストールベースを使用することもできます。この手順では、ベースの Linux システムのインストールに時間がかかります。

```sh
# download mini install image
curl -O http://archive.ubuntu.com/ubuntu/dists/bionic-updates/main/installer-amd64/current/images/netboot/mini.iso
# create qemu image file
qemu-img create -f qcow2 lubuntu.qcow2 5G
# create directory for tpm state and socket
mkdir $PREFIX/mytpm
# start swtpm
$PREFIX/bin/swtpm socket --tpm2 --tpmstate dir=$PREFIX/mytpm \
  --ctrl type=unixio,path=$PREFIX/mytpm/swtpm-sock --log level=20 &
# start qemu for installation
qemu-system-x86_64 -m 1024 -boot d -bios bios-256k.bin -boot menu=on \
  -chardev socket,id=chrtpm,path=$PREFIX/mytpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 -hda lubuntu.qcow2 -cdrom mini.iso
```

ベースシステムのインストール後、QEMU を再び起動し、QEMU インスタンス内で wolfSSL と wolfTPM をビルドします。

```sh
# start swtpm again
$PREFIX/bin/swtpm socket --tpm2 --tpmstate dir=$PREFIX/mytpm \
  --ctrl type=unixio,path=$PREFIX/mytpm/swtpm-sock --log level=20 &
# start qemu system to install and run wolfTPM
qemu-system-x86_64 -m 1024 -boot d -bios bios-256k.bin -boot menu=on \
  -chardev socket,id=chrtpm,path=$PREFIX/mytpm/swtpm-sock \
  -tpmdev emulator,id=tpm0,chardev=chrtpm \
  -device tpm-tis,tpmdev=tpm0 -hda lubuntu.qcow2
```

QEMU のターミナルで、wolfTPM をチェックアウトしてビルドします。

```sh
sudo apt install automake libtool gcc git make

# get and build wolfSSL
git clone https://github.com/wolfssl/wolfssl.git
pushd wolfssl
./autogen.sh && \
  ./configure --enable-wolftpm --disable-examples --prefix=$PWD/../inst && \
  make install
popd

# get and build wolfTPM
git clone https://github.com/wolfssl/wolftpm.git
pushd wolftpm
./autogen.sh && \
  ./configure --enable-devtpm --prefix=$PWD/../inst --enable-debug && \
  make install
sudo make check
popd
```

QEMU 内で `sudo ./examples/wrap/wrap` などのサンプルを実行できます。`/dev/tpm0` にアクセスするために `sudo` が必要になる場合があります。

### サンプルの実行

```sh
./examples/wrap/caps
./examples/pcr/extend
./examples/wrap/wrap_test
```

その他のサンプルの使い方については、ソースツリーの `examples/README.md` を参照してください。

## Linux カーネルデバイス (/dev/tpmX)

Linux では、カーネルの TPM ドライバースタックが TPM をキャラクターデバイスとして公開しており、wolfTPM は SPI や I2C を自前で駆動する代わりに、それを直接使用できます。カーネルがすでに TPM を管理している場合には、このトランスポートが適切です。たとえば、カーネルドライバーにバインドされたディスクリートチップ、Windows 形式のファームウェア TPM、NVIDIA Jetson プラットフォームのような TEE 上で動作するファームウェア TPM などです。

`--enable-devtpm` を指定すると、TIS レイヤーも HAL IO コールバックも存在しません。`hal/tpm_io.c` は完全にコンパイル対象から除外され、`TPM2_IoCb` は `NULL` になります (`hal/tpm_io.h` を参照)。そのため、`TPM2_Init` と `wolfTPM2_Init` のコールバック引数には `NULL` を渡してください。

`--enable-autodetect` を指定した場合はこの限りではありません。TIS/SPI HAL はフォールバックであるため、意図的にコンパイルされたままになり、`TPM2_IoCb` は実在する関数です。これを渡し続けてください。そうしないと、このビルドが提供するはずの SPI フォールバックに到達できなくなります。

### 2 つのデバイスノード

カーネルは、TPM ごとに最大 2 つのノードを提供します。

* `/dev/tpm0`: raw デバイスです。同時に 1 ユーザーのみで、リソース管理はありません。送信したものはそのまま TPM に届きます。
* `/dev/tpmrm0`: カーネル内のリソースマネージャーです (カーネル 4.12 以降、実用的には 5.12 以降)。ハンドルを仮想化し、必要に応じてトランジェントオブジェクトとセッションをスワップイン/スワップアウトし、接続が閉じられると、その接続に属するすべてを解放します。

wolfTPM は `/dev/tpmrm0` を優先し、`/dev/tpm0` にフォールバックします。リソースマネージャーの方が望ましい既定値です。TPM が持つトランジェントオブジェクトのスロットは非常に少なく、リソースマネージャーがないと、ハンドルをリークするプログラムが原因で、システム上の他のすべてのプログラムが TPM を使えなくなるおそれがあります。

`--enable-devtpm` と `--enable-autodetect` のどちらにも適用されるビルド時の上書き設定:

* `-DWOLFTPM_USE_TPMRM`: `/dev/tpmrm0` のみを使用し、raw デバイスにはフォールバックしません。
* `CFLAGS='-DTPM2_LINUX_DEV="/dev/tpm1"'`: 特定のノードを使用します。このマクロは C の文字列リテラルとして直接使用されるため、内側の引用符が必要です。引用符がないとコンパイルできません。

### スタートアップ、シャットダウン、共有状態

TPM は Linux が動作するずっと前にファームウェアによって起動されており、リソースマネージャー経由では、システム上の他のすべてのプロセスと共有されます。したがって、TPM の再起動やシャットダウンは個々の呼び出し元が決めることではなく、wolfTPM はこのトランスポートでは介入しません。

* `wolfTPM2_Init` は、スタートアップとセルフテストのシーケンスを省略します。
* `wolfTPM2_Reset` と `wolfTPM2_Shutdown` は TPM コマンドを送信せず、`NOT_COMPILED_IN` (-174) を返します。このトランスポートでの `wolfTPM2_SetLocality` と同様です。シャットダウンもスタートアップも要求しない `wolfTPM2_Reset(dev, 0, 0)` は、拒否したものが何もないため、引き続き `TPM_RC_SUCCESS` を返します。ここでの `NOT_COMPILED_IN` は、失敗ではなく「OS が管理している」という意味に捉えてください。
* `wolfTPM2_SetLocality` は、カーネルがロカリティを管理しているため `NOT_COMPILED_IN` を返します。

カーネルがこの点を確実に防いでくれるわけではありません。`/dev/tpmrm0` でのコマンドフィルタリングは、主にハンドルの分離のためのものであり、グローバルな状態変更をブロックするためのものではありません。また、動作はカーネルのバージョンや TPM の実装によって異なります。Jetson OP-TEE fTPM を搭載した Linux 5.15 では、リソースマネージャー経由で送信した `TPM2_Shutdown(TPM_SU_CLEAR)` はそのまま通過して成功を返します。これは wolfTPM からでも `tpm2_shutdown` からでも同じです。つまりこれは、カーネルではなく、ライブラリがコマンドの送信を見送ることで TPM の他の利用者を守っているケースです。

TPM のスタートアップ状態を制御する必要がある場合は、`/dev/tpm0` と TPM の排他的な使用、または wolfTPM の TIS ドライバーによる SPI 直接アクセスが必要です。

### autodetect ビルドでのネイティブ API の動作

`wolfTPM2_*` ラッパーではなく `TPM2_Init` または `TPM2_Init_ex` を直接使用する場合は、次の 2 つの動作に注意が必要です。

カーネルデバイスは、渡したコールバックより優先されます。`/dev/tpmrm0` または `/dev/tpm0` が開ければ、すべてのコマンドがそこへルーティングされ、渡した HAL IO コールバックは一切呼び出されません。カーネルにバインドされた TPM とディスクリートの SPI 部品の両方があるホストでは、autodetect 導入前のビルドとは別の TPM と通信することになります。使用したい部品は、`--enable-devtpm`、`--enable-spi`、`--enable-<vendor>`、または `-DTPM2_LINUX_DEV` で固定してください。

初期化でディスクリプターが取得されるようになりました。autodetect ビルドでは `TPM2_Init*` がデバイスを開き、それを閉じるのは `TPM2_Cleanup()` です。クリーンアップを省略していたネイティブの呼び出し元は、以前は何もリークしませんでしたが、現在はコンテキストごとにディスクリプターをリークします。これは、単一のオープンしか許可しない raw の `/dev/tpm0` のみを公開しているホストで最も問題になります。初期化しただけのコンテキストが、その存続期間中ずっと TPM を排他的に保持し、同じプロセス内の 2 つ目のコンテキストは別のトランスポートにフォールスルーします。

`TPM2_Init_minimal()` は影響を受けません。IO を一切行わず、デバイスが存在しなくても成功します。

### トランジェントハンドルはプロセスをまたいで存続しない

これは、既存のアプリケーションが動作しなくなる原因として最も可能性が高い違いです。

`/dev/tpmrm0` では、カーネルがオープンしたファイル記述ごとに専用のハンドル空間を与えます。トランジェントオブジェクトのハンドルは仮想化され (TPM が割り当てた値と、返される値は異なります)、その空間内のすべてのものは、ファイルディスクリプターが閉じられると解放されます。あるプロセスで作成したトランジェント鍵は、次のプロセスが実行される時点ではすでに存在せず、そのプロセスが出力したハンドル番号は他のプロセスにとって意味を持ちません。

リソースマネージャー経由で Jetson fTPM 上にプライマリ鍵を作成すると、次のように返されます。

```
Create Primary Handle: 0x80ffffff
```

これは、raw デバイスが報告する `0x80000000` ではありません。その後、別のプロセスからトランジェントハンドルを問い合わせると、リストは空です。

```bash
tpm2_getcap handles-transient      # no output, the space was torn down
```

実際上の帰結は次の 2 つです。

* 「鍵を作成して保持し、次のコマンドで使う」というワークフローは、プロセスをまたいでは機能しません。一連の処理を 1 つのプロセス内で行うか、`TPM2_EvictControl` でオブジェクトを永続化して、存続する安定した `0x81xxxxxx` ハンドルを割り当ててください。
* `0x80000000` のようなトランジェントハンドルをコマンドラインにハードコードして渡すと失敗します。カーネルが TPM に届く前にその参照を拒否し、これはファイルディスクリプター層で起きるため、エラーは `read()` での `errno 22 = Invalid argument` として表面化し、wolfTPM はこれをハンドルエラーではなく `TPM_RC_FAILURE` として報告します。`TPM_RC_FAILURE` が `Failed to read from /dev/tpmrm0 ... errno 22` とともに表示される場合は、TPM を疑う前に、古い、またはプロセスをまたいだトランジェントハンドルを疑ってください。

wolfTPM のスクリプト `examples/run_examples.sh` はまさにこの問題に当たります。プロビジョニングのセクションで、あるプロセスが `-keep` を付けて IAK と IDevID のプライマリ鍵を作成し、別のプロセスから `0x80000000` と `0x80000001` を参照します。このブロックは、構造上、リソースマネージャーでは成功しません。その前後の部分は影響を受けません。記述どおりに実行する必要がある場合は、排他アクセスで `/dev/tpm0` を使用してください。

### ビルド

```bash
./autogen.sh
./configure --enable-devtpm
make
```

`--enable-devtpm` はカーネルノードのみを使用します。wolfTPM に `/dev/tpmrm0`、次に `/dev/tpm0` を試させ、最後に SPI のプローブにフォールバックさせたい場合は、代わりに `--enable-autodetect` を使用してください。これは、複数のボードで動作させる必要がある 1 つのバイナリに便利です。

有効にできるトランスポートは一度に 1 つだけです。`--enable-devtpm` は `--enable-swtpm` および `--enable-winapi` と競合し、複数を指定すると configure は停止します。

#### x86_64 および aarch64 の既定動作

Linux の x86_64 または aarch64 でオプションなしの `./configure` を実行しても、`/dev/tpmX` と通信するビルドにはなりません。これらのホストでは、ハードウェアなしで `make check` が成功するように、wolfTPM がソフトウェア TPM (swTPM と fwTPM) を自動的に有効にし、`WOLFTPM_SWTPM` が定義されるとカーネルデバイスの autodetect 経路は抑止されます。その結果、TCP ポート 2321 のシミュレーターと通信するビルドになります。

ハードウェア経路を明示的に選択すると、この既定動作は再び無効になります: `--enable-autodetect`、`--enable-devtpm`、または任意の `--enable-<vendor>` です。ソフトウェアの既定値が採用された場合、configure は通知を出力します。ビルドしたバイナリが TPM を見つけられない場合は、configure の出力の末尾を確認してください。

これは、ファームウェア TPM を搭載したシングルボードの aarch64 マシンで特に重要です。そこではカーネルデバイスが唯一のトランスポートだからです。

### パーミッション

TPM のキャラクターデバイスは、全ユーザーがアクセスできる設定ではありません。一般的なシステムでは、モードは `0660` で、グループ `tss` が所有しています。

```
crw-rw---- 1 tss root  10,   224 /dev/tpm0
crw-rw---- 1 tss tss  252, 65536 /dev/tpmrm0
```

wolfTPM は `EACCES` を検出し、そのことを分かりやすく報告します。

```
Permission denied on /dev/tpm0
Use sudo or add tss group to user.
```

対処方法は、ユーザーを所有グループに追加し、新しいログインセッションを開始することです。

```bash
sudo usermod -aG tss $USER
```

`tss` グループは tpm2-tss によって作成されます。これを提供するディストリビューションでは、このグループがメンバーなしで存在していることがよくあります。そのため、グループが正しく設定されているように見えても、この手順は必須です。

独自のグループを使用する場合は、代わりに udev ルールを追加します。

1. グループを作成し、ユーザーを追加します。

    ```bash
    sudo addgroup wolftpm
    sudo adduser [username] wolftpm
    ```

2. 次の内容で `/etc/udev/rules.d/wolftpm-udev.rules` を作成します。

    ```
    KERNEL=="tpm[0-9]*", TAG+="systemd", MODE="0660", GROUP="wolftpm"
    ```

3. `sudo udevadm control -R` でルールを再読み込みし、再接続または再起動します。

### NVIDIA Jetson Orin (Tegra234) ファームウェア TPM

Jetson Orin プラットフォームには、バス上のディスクリートパッケージではなく、OP-TEE 内のトラステッドアプリケーションとして動作するファームウェアで実装された TPM 2.0 が搭載されています。Linux は `tpm_ftpm_tee` ドライバー経由でこれにアクセスします。このドライバーは TEE インターフェースを介して TA と通信し、通常の TPM チップとして登録されます。wolfTPM から見ると、それは単なる別の `/dev/tpmrm0` です。

ビルドする前に、デバイスが存在することを確認します。

```bash
lsmod | grep tpm_ftpm_tee
ls -l /dev/tpm*
cat /sys/class/tpm/tpm0/tpm_version_major     # expect 2
```

モジュールがない場合は、`sudo modprobe tpm_ftpm_tee` を試し、カーネルが `CONFIG_TCG_FTPM_TEE` を有効にして構成されていることを確認してください。NVIDIA Jetson Linux (L4T) イメージにはこのドライバーが含まれており、起動時に `fTPM Device Provisioning Service` の systemd ユニットが実行されます。その完了は起動ログで確認できます。

シリコン ID の fTPM プロビジョニングが有効でないという OP-TEE の起動メッセージは、NVIDIA の別の機能に関するものです。TPM 2.0 デバイスが利用できないという意味ではありません。

上記のとおり `--enable-devtpm` または `--enable-autodetect` を指定してビルドし、次のコマンドで確認します。

```bash
./examples/wrap/caps
```

ファームウェア TPM であるため、ディスクリートの部品とは 2 つの点で違いがあります。まず、TIS バスがないため、`TPM2: Caps/Did/Vid/Rid` の値は存在せず、デバイスは `TPM2_GetCapability` のプロパティのみから識別されます。`--enable-devtpm` では `DEBUG_WOLFTPM` の行は引き続き出力されますが、すべてゼロになります。`--enable-autodetect` では、`wolfTPM2_Init_ex` はカーネルデバイスが開いた時点で、その printf の前に戻るため、この行は完全に出力されません。次に、ファームウェア TPM のアルゴリズムのカバー範囲は、データシートではなくファームウェアのビルドによって決まるため、想定せずに確認してください。操作が存在しない場合、ベンチマークは失敗ではなく未サポートとして報告します。Jetson Orin の fTPM は、ベンチマークが実行するすべての操作をサポートしています。

### テスト

サンプルは、このトランスポートでも変更なしで動作します。

```bash
./examples/wrap/caps
./examples/native/native_test
./examples/wrap/wrap_test
./examples/bench/bench
./examples/run_examples.sh
```

`run_examples.sh` は、ロカリティテストをサポートしないバックエンドでは、すでにそのテストをスキップします。

### CI でのカバレッジ

`--enable-devtpm` と `--enable-autodetect` はどちらも CI でビルドテストされていますが、GitHub ホストのランナーには `/dev/tpm*` ノードがないため、実行はされていません。このトランスポートの実行時カバレッジには、カーネルドライバーにバインドされた実際の TPM を備えたセルフホストランナーが必要です。

## Windows TBS API

wolfTPM は、Windows ネイティブの TBS (TPM Base Services) を使用するようにビルドできます。Windows TBS インターフェースを使用する場合、NV へのアクセスは既定でブロックされます。TPM の NV ストレージ領域は非常に限られており、満杯になると、鍵ハンドルのロード失敗など、未定義の動作を引き起こす可能性があります。NV 領域は TBS によって管理されません。

TPM は、`TPM2_Create` による鍵の作成時に、暗号化された秘密鍵ブロブを返すよう設計されています。これはディスクに安全に保存し、必要なときにロードできます。秘密鍵ブロブの保護に使用される対称暗号鍵は、TPM だけが知っています。`TPM2_Load` で鍵をロードするとトランジェントハンドルが得られ、これを署名、および暗号化と復号に使用できます。

`TPM2_CreatePrimary` で作成したプライマリ鍵では、ハンドルが返されます。暗号化された秘密データは返されません。このハンドルは、`TPM2_FlushContext` が呼び出されるまでロードされたままです。

`TPM2_Create` による通常の鍵作成では、`TPM2B_PRIVATE outPrivate` が返されます。これは暗号化されたブロブで、保存しておき、`TPM2_Load` でいつでもロードできます。

### 制限事項

wolfTPM は、TPM 2.0 デバイスを搭載した Windows 10 でテストされています。Windows は TPM 1.2 もサポートしていますが、機能は限定的であり、wolfTPM は TPM 1.2 をサポートしません。

TPM 2.0 の有無は、PowerShell を開いて `Get-PnpDevice -Class SecurityDevices` を実行して確認できます。

```
Status     Class           FriendlyName
------     -----           ------------
OK         SecurityDevices Trusted Platform Module 2.0
Unknown    SecurityDevices Trusted Platform Module 2.0
```

### MSYS2 でのビルド

MSYS2 を使用してテストしました。

```bash
export PREFIX=$PWD/tmp_install

cd wolfssl
./autogen.sh
./configure --prefix="$PREFIX" --enable-wolftpm
make
make install

cd wolftpm/
./autogen.sh
./configure --prefix="$PREFIX" --enable-winapi
make
./examples
```

MSYS2 に開発用の基本ツールをインストールするには、`pacman -S base-devel` と `pacman -S mingw-w64-x86_64-toolchain` を使用します。

### Linux でのビルド

[MinGW-w64 Win32 toolchain builds](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win32/Automated%20Builds/) の mingw-w32-bin_x86_64-linux_20131221.tar.bz2 を使用してテストしました。

ツールを展開し、`PATH` に追加します。

```bash
mkdir mingw_tools
cd mingw_tools
tar xjvf ../mingw-w32-bin_x86_64-linux_20131221.tar.bz2
export PATH=$PWD/bin/:$PWD/i686-w64-mingw32/bin:$PATH
cd ..
```

ビルド:

```bash
export PREFIX=$PWD/tmp_install
export CFLAGS="-DWIN32 -DMINGW -D_WIN32_WINNT=0x0600 -DUSE_WOLF_STRTOK"
export LIBS="-lws2_32"

cd wolfssl
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc --prefix="$PREFIX" --enable-wolftpm
make
make install

cd ../wolftpm/
./autogen.sh
./configure --host=i686 CC=i686-w64-mingw32-gcc --prefix="$PREFIX" --enable-winapi
make
cd ..
```

### Windows での実行

マシン上の TPM の有無と状態を確認するには、`tpm.msc` を実行します。サンプルの実行方法については、ソースツリーの `examples/README.md` を参照してください。

## 関連項目

- [はじめに](getting-started.md)
- [wolfTPM のビルド](building.md)
- [ビルドオプション](build-options.md)
- [対応ハードウェア](supported-hardware.md)
