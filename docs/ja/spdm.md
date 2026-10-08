# SPDM アテステーションとセキュアセッション

wolfTPM には、wolfSSL/wolfCrypt を使用した、Nuvoton NPCT75x および Nations NS350 TPM 向けの SPDM (Security Protocol and Data Model、DMTF DSP0274) サポートが組み込まれています。SPDM は、TCG の SPDM-over-TPM バインディング上でプロトコルバージョン 1.3 をネゴシエートします。両ベンダーとも、セッション確立のためのアイデンティティ鍵モード (ECDHE P-384) をサポートしています。Nations NS350 は、さらに PSK (事前共有鍵) モードもサポートしています。セッションが確立されると、すべての TPM コマンドとレスポンスは、既存の SPI または I2C バス上で AES-256-GCM により暗号化されます。アイデンティティ鍵モードでは、信頼できるプロビジョニング元から得たレスポンダーの P-384 公開鍵が必要です。TCG の交換は生の公開鍵の交換 (GET_PUBK と GIVE_PUB) であり、証明書は交換されません。

SPDM のコードは [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) ライブラリにあり、`lib/wolfSPDM` サブモジュールとして含まれ、TPM プロファイルで libwolftpm にコンパイルされます。SPDM を使用するチェックアウトには、再帰的なクローン、または後からの初期化によって、このサブモジュールが存在している必要があります。サブモジュールがない場合、`./configure --enable-spdm` は次のメッセージで停止します: `--enable-spdm needs the wolfSPDM submodule: run git submodule update --init lib/wolfSPDM`。

## クイックスタート

SPDM は `lib/wolfSPDM` サブモジュールにあるため、再帰的にクローンします。

```sh
git clone --recursive https://github.com/wolfSSL/wolfTPM.git
git clone https://github.com/wolfSSL/wolfssl.git   # sibling checkout
cd wolfTPM
```

`--recursive` なしでクローン済みの場合は、チェックアウト内で `git submodule update --init lib/wolfSPDM` を一度実行してください。

### Nuvoton NPCT75x

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nuvoton && make

# Enable SPDM (one-time), reset (see TPM reset pin control), connect
./examples/spdm/spdm_ctrl --enable
timeout 0.1 gpioset --chip gpiochip0 4=0; gpioset --chip gpiochip0 --daemonize 4=1; sleep 2
RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
./examples/spdm/spdm_ctrl --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

上記の GPIO ラインの指定は libgpiod 2.x 形式です。libgpiod 1.x 形式と注意事項については、TPM リセットピン制御のセクションを参照してください。`responder_pubkey.hex` には、プロビジョニング記録から得た、信頼できる生の P-384 X||Y 点 (192 文字の 16 進数) が格納されています。

### Nations NS350

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nations && make

# Connect (identity key is factory default)
RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
./examples/spdm/spdm_ctrl --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

## 概要と動作の仕組み

`spdm_ctrl` ツールは、ホストと TPM の間に SPI 経由で SPDM セキュアセッションを確立し、AES-256-GCM で暗号化されたバス通信を可能にします。実装は Algorithm Set B (SHA-384 と AES-256-GCM) を使用し、アイデンティティ鍵モードではこれに ECDH P-384、ECDSA P-384、HKDF-SHA384 が加わります。セッション確立モードは 2 つサポートされています。

SPDM の資格情報を受け付けるサンプルは `spdm_ctrl` と `nv_bind` です。その他の wolfTPM サンプルは、資格情報なしの `wolfTPM2_Init()` を使用しており、TPM が SPDM 専用モードでロックされている間は意図的に `WOLFSPDM_E_BAD_STATE` を返します。それらのサンプルを実行する前に、`spdm_ctrl` でロックを解除してください。

サポートされるハードウェア:

- Nuvoton NPCT75x: アイデンティティ鍵モード (ECDHE P-384)
- Nations NS350: アイデンティティ鍵モードおよび PSK モード

### アイデンティティ鍵モード (Nuvoton と Nations)

```
Host                                TPM (Nuvoton NPCT75x / Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>|  (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                   |
  |--- GET_CAPABILITIES ------------->|  (Nations only)
  |<-- CAPABILITIES ------------------|
  |--- NEGOTIATE_ALGORITHMS --------->|  (Nations only)
  |<-- ALGORITHMS --------------------|
  |                                   |
  |--- GET_PUBK --------------------->|  (get TPM's P-384 identity key)
  |<-- GET_PUBK response -------------|
  |                                   |
  |--- KEY_EXCHANGE ----------------->|  (ECDHE P-384 key agreement)
  |<-- KEY_EXCHANGE_RSP --------------|  (+ ECDSA signature and HMAC)
  |                                   |
  |    --- Handshake keys derived --- |
  |                                   |
  |=== GIVE_PUB =====================>|  (encrypted: host's P-384 key)
  |<== GIVE_PUB response =============|
  |                                   |
  |=== FINISH =======================>|  (encrypted: signature + HMAC)
  |<== FINISH_RSP ====================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>|  (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

Nuvoton アダプターは GET_CAPABILITIES と NEGOTIATE_ALGORITHMS を省略します。Nations アダプターは VERSION の後にこれらを送信します。ハンドシェイクでは、鍵合意に ECDH P-384、署名に ECDSA P-384、鍵導出に HKDF-SHA384、認証に HMAC-SHA384 を使用します。PSK の鍵合意には P-384 は含まれません。ハンドシェイク後、すべての TPM コマンドは SPDM の `VENDOR_DEFINED_REQUEST("TPM2_CMD")` メッセージでラップされ、AES-256-GCM で暗号化されます。TPM のレスポンスは `VENDOR_DEFINED_RESPONSE` メッセージで返されます。セキュアレコードは、リクエストとレスポンスそれぞれに独立した 64 ビットのシーケンス番号を持ち、リプレイ攻撃を防ぐためにメッセージごとにインクリメントされます。

### PSK モード (Nations のみ)

PSK モードは、ECDHE 鍵交換を対称の事前共有鍵に置き換えます。データ転送には同じ AES-256-GCM 暗号化が使用されます。リクエスターは GET_VERSION から直接 PSK_EXCHANGE に進み、このフローではケイパビリティとアルゴリズムのネゴシエーションは不要です。

```
Host                                TPM (Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>| (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                   |
  |--- PSK_EXCHANGE ----------------->| (session key from PSK)
  |<-- PSK_EXCHANGE_RSP --------------| (+ HMAC proof)
  |                                   |
  |    --- Handshake keys derived --- | (Salt_0 = 0xFF * H for PSK mode)
  |                                   |
  |=== PSK_FINISH ===================>| (encrypted: requester HMAC)
  |<== PSK_FINISH_RSP ================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>| (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

NS350 では、PSK モードとアイデンティティ鍵モードは排他的です。アイデンティティ鍵は工場出荷時にプロビジョニングされており、PSK を使用する前に解除する必要があります。PSK ライフサイクルのセクションを参照してください。

### SPDM 専用モード (暗号化バスの強制)

SPDM 専用モードは、TPM コマンドを暗号化された SPDM チャネル経由に強制します。唯一の例外は平文の `TPM2_GetCapability` で、これはサポート対象のシリコンに合わせて、ロック中も fwTPM レスポンダーが意図的に許可しています。両ベンダーが SPDM 専用モードをサポートしています。典型的なライフサイクルは次のとおりです。

```
1. Enable SPDM        (one-time, persists across resets)
2. Connect            (handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects cleartext commands except GetCapability)
4. Reset              (TPM enters SPDM-only enforcement)
5. Initialize with the trusted key or PSK and run commands (all encrypted)
6. Unlock             (connect + unlock in one session)
7. Reset              (TPM back to normal cleartext mode)
```

アプリケーションが `wolfTPM2_InitWithSpdmKey()` を通じてレスポンダー鍵を提供した後、wolfTPM はレスポンダーを認証して暗号化セッションを確立します。起動プローブが成功した場合、すでに初期化済みであった場合、または想定される `TPM_RC_DISABLED` の結果となった場合は、処理を継続します。ファームウェアアップグレード状態などのその他の起動失敗は、SPDM 接続が試みられる前に返されます。詳細は Auto-SPDM のセクションを参照してください。

リセット方法はベンダーによって異なります。

- Nuvoton: GPIO 4 によるリセット (TPM リセットピン制御を参照)
- Nations: テストハーネスで使用される NS350 のドーターボードでは GPIO 4 が TPM_RST に配線されているため、同じ GPIO リセットが適用されます。お使いのボードで配線されていない場合は、完全な電源の入れ直しを行ってください。

## ビルド

### 1. wolfSPDM サブモジュールを含めてクローンする

クイックスタートのセクションを参照してください。SPDM は `lib/wolfSPDM` サブモジュールからビルドされるため、wolfTPM を再帰的にクローンするか、既存のチェックアウトで `git submodule update --init lib/wolfSPDM` を実行してください。

### 2. wolfSSL

Nuvoton と Nations は同じ wolfSSL フラグを使用します。これらは SPDM Algorithm Set B のための暗号処理を提供します。wolfSSL 5.8.0 以降が必要で、wolfSPDM の configure チェックがこれを強制します。このチェックは `lib/wolfSPDM` サブモジュール内にあり、このページのレビューに使用したツリーには存在しなかったため、正確な最小バージョンはそちらで確認してください。

```sh
cd ../wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
    --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install && sudo ldconfig
cd -   # back to the wolfTPM checkout
```

### 3. wolfTPM

```sh
./autogen.sh
./configure --enable-spdm --enable-nuvoton   # Nuvoton
# or
./configure --enable-spdm --enable-nations    # Nations
make
```

`--enable-spdm` に加えて、少なくとも 1 つのハンドシェイクモードを指定してビルドします。TCG の生の公開鍵ハンドシェイクには `--enable-tcg`、PSK ハンドシェイクには `--enable-psk` です。ベンダー固有のワイヤフォーマットアダプター (`--enable-nuvoton`、`--enable-nations`) は任意です。

### wolfTPM の SPDM プロファイル

`--enable-spdm` は `WOLFTPM_SPDM` を定義し、これにより wolfSPDM の `WOLFSPDM_PROFILE_TPM` が自動的に選択されます。TPM のバインディングは TCG SPDM Binding であるため、このプロファイルは TCG に特化した軽量ビルドです。以下の汎用 DSP0274 リクエスター機能は、自動的にコンパイルから除外されます。Nations アダプターは、`spdm_tcg.c` 内にある独自の TCG 固有の GET_CAPABILITIES および NEGOTIATE_ALGORITHMS の実装を引き続き使用します。

- DMTF 標準のリクエスター機能: `GET_CAPABILITIES`、`NEGOTIATE_ALGORITHMS`、`GET_DIGESTS`、`GET_CERTIFICATE`、および証明書チェーンの検証
- 測定 (measurements)、チャレンジ、チャンキング (これらは証明書フローに付随します)
- ハートビートと鍵更新
- MCTP アプリケーションデータ API (セキュアメッセージは TCG の 16 バイトパディングを使用します)

wolfTPM の `configure` には `--disable-mctp` オプションはなく、追加しようとしてもいけません。軽量プロファイルは `--enable-spdm` で自動的に適用され、wolfSPDM の下流 CI は、上記の標準リクエスターのシンボルが `libwolftpm` に存在しないことを検証します。

このプロファイルは `WOLFSPDM_NO_MCTP` を定義しないため、MCTP のセキュアメッセージフレーミングはコンパイルされたままですが、TCG 専用の TPM がこれを使用することはありません。wolfSPDM を単体で `--disable-mctp` (`--enable-tcg` が必要) を付けてビルドすると、純粋な TCG リクエスター向けにその経路がさらに除去されます。このフラグは wolfSPDM 自身の `configure` のものであり、wolfTPM のものではありません。

### configure オプション

| オプション | 説明 |
|--------|-------------|
| `--enable-spdm` | SPDM サポートを有効化 (必須) |
| `--enable-tcg` | TCG SPDM Binding 仕様のハンドシェイク (fwtpm/nuvoton/nations が有効な場合は自動) |
| `--enable-psk` | DSP0274 PSK ハンドシェイク (`--enable-nations` で自動、`--enable-tcg` が必要) |
| `--enable-fwtpm` | SPDM レスポンダー付きの fwtpm_server をビルド (シリコン不要) |
| `--enable-nuvoton` | Nuvoton TPM ハードウェアサポートを有効化 (`--enable-tcg` を自動的に有効化) |
| `--enable-nations` | Nations NS350 ハードウェアサポートを有効化 (`--enable-tcg --enable-psk` を自動的に有効化) |
| `--enable-debug` | 詳細な SPDM トレース付きのデバッグ出力 |
| `--enable-smallstack` | ヒープに確保される SPDM コンテキストとコマンドごとのメッセージバッファ (デフォルト: 呼び出し側が所有するインラインコンテキスト、約 32 KB) |

`configure` は、次の互換性のない組み合わせを拒否します。

- `--enable-nuvoton --disable-tcg` (Nuvoton は TCG SPDM Binding を使用します)
- `--enable-nations --disable-tcg` または `--enable-nations --disable-psk`
- `--enable-psk --disable-tcg` (PSK は TCG のフレーミング上で動作します)

### fwTPM SPDM レスポンダー (シリコン不要)

`fwtpm_server` には SPDM 1.3 レスポンダーが含まれており、実際の Nuvoton および Nations のデバイスが使用するのと同じハンドシェイクを駆動します。これにより、実ハードウェアなしで CI 上で TCG と PSK のスタック全体を検証できます。

ソケットレスポンダーを有効にしてビルドします。

```sh
./configure --enable-fwtpm --enable-swtpm --enable-spdm --enable-tcg --enable-psk
make
```

その後、SPDM モードのいずれかで起動します。PSK は 64 バイト (16 進数 128 文字) の完全な値でなければなりません。以下の値は `spdm_test.sh` で使用されるテスト用 PSK です。

```sh
SPDM_PSK=dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047
./src/fwtpm/fwtpm_server --spdm-tcg                              # TCG raw public key handshake
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK"   # PSK handshake
```

手動で PSK をテストする場合は、同じ `SPDM_PSK` の値をリクエスターに渡します。たとえば `spdm_ctrl --psk "$SPDM_PSK"` のようにします。

エンドツーエンドでテストします。

```sh
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-tcg
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-psk
```

レスポンダーのモードとエンドツーエンドのテストスクリプトについては、[fwtpm/spdm.md](fwtpm/spdm.md) を参照してください。

### デュアルベンダービルドでのベンダー選択

`--enable-nuvoton` と `--enable-nations` の両方がコンパイルされている場合、`spdm_ctrl` は任意のランタイムフラグでベンダーアダプターを選択します。

```sh
./examples/spdm/spdm_ctrl --vendor=nuvoton \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect
./examples/spdm/spdm_ctrl --vendor=nations \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect
```

単一ベンダーのビルドは、バイナリにコンパイルされたアダプターのみを受け付け、利用できない `--vendor=` の値を拒否します。

## 使い方と制御コマンド

### 初回セットアップ

管理コマンド (有効化、無効化、アイデンティティ鍵の設定と解除) は空のプラットフォーム認可を使用し、`--tpm-clear` はデフォルトの空のロックアウト認可を使用します。`spdm_ctrl` には異なる階層シークレットを指定するオプションがないため、これらのコマンドは、空でない認可でプロビジョニングされた TPM では動作しません。

Nuvoton:

```sh
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_ctrl --enable

# Reset the TPM (see TPM reset pin control)

# Verify SPDM is enabled
./examples/spdm/spdm_ctrl --status
```

Nations: アイデンティティ鍵モードが工場出荷時のデフォルトであるため、セットアップは不要です。以前に解除した場合は、次のコマンドで復元します。

```sh
./examples/spdm/spdm_ctrl --identity-key-set
```

### セッションの確立

アイデンティティ鍵モード (両ベンダー):

```sh
# Establish SPDM session (VERSION, GET_PUBK, KEY_EXCHANGE, GIVE_PUB, FINISH;
# Nations also sends GET_CAPABILITIES and NEGOTIATE_ALGORITHMS)
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect

# Query SPDM status
./examples/spdm/spdm_ctrl --status
```

`--responder-pubkey` は、信頼できる生の P-384 X||Y 点を 192 文字の 16 進数で受け取ります。デバイスのプロビジョニング記録、または認証されたその他の製造元チャネルから入手してください。ここでの例では、シークレットをシェル変数に読み込んでいます。たとえば `RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"` のようにします。資格情報ファイルは、所有者のみが読み取れるようにしてください (`chmod 600`)。

!!! warning
    `--get-pubkey` は認証なしの探索であり、それ単体で信頼を確立するために使用してはいけません。

PSK モード (Nations) では、先に PSK をプロビジョニングする必要があります。PSK ライフサイクルのセクションを参照してください。以下のコマンドでは、`PSK_HEX` は 128 文字の 16 進数で表した 64 バイトの PSK を、`CLEARAUTH_HEX` は 64 文字の 16 進数で表した 32 バイトの ClearAuth を保持します。いずれも、自分だけが読み取れるファイルから読み込みます。

```sh
# Establish PSK session (VERSION, PSK_EXCHANGE, PSK_FINISH)
./examples/spdm/spdm_ctrl --psk "$PSK_HEX"
```

### SPDM 専用モードのロックとロック解除

ロックにはアクティブな SPDM セッションが必要です。ロック後、強制を有効にするにはリセットが必要です。

Nuvoton (アイデンティティ鍵):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM (see TPM reset pin control)

# Unlock
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM again
```

Nations (アイデンティティ鍵):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM (GPIO 4 on the tested board, otherwise a power cycle)

./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM again
```

Nations (PSK モード):

```sh
./examples/spdm/spdm_ctrl --psk "$PSK_HEX" --lock
# Reset the TPM

./examples/spdm/spdm_ctrl --psk "$PSK_HEX" --unlock
# Reset the TPM again
```

### PSK ライフサイクル (Nations)

NS350 では、PSK モードとアイデンティティ鍵モードは排他的です。アイデンティティ鍵はデフォルトでプロビジョニングされており、PSK を使用する前に解除する必要があります。

```sh
# 1. Unset identity key (enables PSK mode)
./examples/spdm/spdm_ctrl --identity-key-unset

# 2. Provision PSK (64-byte PSK + 32-byte ClearAuth)
#    The demo computes SHA-384(ClearAuth) and sends PSK(64)+Digest(48) = 112 bytes
./examples/spdm/spdm_ctrl --psk-set "$PSK_HEX" "$CLEARAUTH_HEX"

# 3. Establish PSK session
./examples/spdm/spdm_ctrl --psk "$PSK_HEX"

# 4. Clear PSK (sends raw 32-byte ClearAuth; TPM verifies SHA-384 internally)
./examples/spdm/spdm_ctrl --psk-clear "$CLEARAUTH_HEX"

# 5. Restore identity key (factory default)
./examples/spdm/spdm_ctrl --identity-key-set
```

!!! warning
    ClearAuth は正確に 32 バイトでなければなりません。PSK_SET はその SHA-384 ダイジェスト (48 バイト) を保存します。PSK_CLEAR は生の 32 バイトを送信し、TPM が検証のために SHA-384 を計算します。`spdm_ctrl` は、長さが誤った ClearAuth を拒否します。

### コマンドリファレンス

`spdm_ctrl` のすべてのオプション:

| オプション | ベンダー | 説明 |
|--------|--------|-------------|
| `--enable` | Nuvoton | NTC2_PreConfig 経由で SPDM を有効化 (一度だけ、永続、リセットが必要) |
| `--disable` | Nuvoton | NTC2_PreConfig 経由で SPDM を無効化 (リセットが必要) |
| `--identity-key-set` | Nations | SPDM アイデンティティ鍵をプロビジョニング (工場出荷時のデフォルト) |
| `--identity-key-unset` | Nations | プロビジョニング済みのアイデンティティ鍵を削除 (PSK の前に必要) |
| `--vendor=nuvoton\|nations` | 両方 | アイデンティティ/ベンダーアダプターを明示的に選択 |
| `--get-pubkey` | 両方 | 認証せずに TPM のアイデンティティ鍵を探索 |
| `--responder-pubkey` *hex* | 両方 | 信頼できる生の P-384 X\|\|Y レスポンダー鍵を固定 (192 文字の 16 進数) |
| `--connect` | 両方 | アイデンティティ鍵 SPDM セッションを確立 (ECDH P-384 ハンドシェイク) |
| `--caps` | 両方 | 現在のトランスポート経由で TPM のケイパビリティを読み取る |
| `--status` | 両方 | SPDM の状態を照会 |
| `--session-info` | 両方 | TPM から見た SPDM セッションを表示 (`TPM_CAP_SPDM_SESSION_INFO`) |
| `--policy-nv` | 両方 | `TPM2_PolicyTransportSPDM` で保護された NV インデックスを定義し、セッション経由で書き込みと読み取りを行う |
| `--lock` | 両方 | SPDM 専用モードをロック (`--connect` と併用、アクティブなセッションが必要) |
| `--unlock` | 両方 | SPDM 専用モードのロックを解除 (`--connect` と併用、アクティブなセッションが必要) |
| `--psk` *hex* | Nations | PSK セッションを確立 (64 バイトの PSK) |
| `--psk-set` *psk* *clearauth* | Nations | PSK をプロビジョニング (64 バイトの PSK、32 バイトの ClearAuth) |
| `--psk-clear` *clearauth* | Nations | PSK をクリア (32 バイトの ClearAuth) |
| `--caps184` | Nations | TPM 184 ベンダープロパティと SPDM セッション情報を照会 |
| `--tpm-clear` | 両方 | 現在のトランスポート経由で `TPM2_Clear` を送信 (`TPM_RH_LOCKOUT` で認可、デフォルトは空のロックアウト認可) |

### 使用例

```sh
# One-time setup: enable SPDM + reset TPM
./examples/spdm/spdm_ctrl --enable
# Reset the TPM (see "TPM reset pin control" below)

# Query SPDM status
./examples/spdm/spdm_ctrl --status

# Discover TPM identity key (unauthenticated; do not use as its own trust source)
./examples/spdm/spdm_ctrl --get-pubkey

# Establish SPDM session with a key from trusted provisioning records
./examples/spdm/spdm_ctrl \
    --vendor=nuvoton --responder-pubkey "$RESPONDER_PUBKEY" --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --lock
# Reset the TPM

# Unlock SPDM-only mode
./examples/spdm/spdm_ctrl \
    --responder-pubkey "$RESPONDER_PUBKEY" --connect --unlock
# Reset the TPM
```

### nv_bind

`nv_bind` サンプルは、`--policy-nv` の考え方に焦点を当てた、自己完結型のバージョンです。`authPolicy` が `TPM2_PolicyTransportSPDM` である NV インデックスをプロビジョニングし、SPDM-PSK セッション経由でシークレットを保存したうえで、通常の (SPDM ではない) 接続経由での同一の読み取りが `TPM_RC_CHANNEL` で拒否されることを示します。

```sh
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK" --clear &
./examples/spdm/nv_bind --psk "$SPDM_PSK"
```

fwTPM は起動のたびに新しい SPDM アイデンティティ鍵を生成するため、fwTPM 上では `tpmKeyName` にバインドされたポリシーはそのサーバーの存続期間中のみ有効です。ハードウェア TPM は永続的なアイデンティティ鍵を保持しているため、そのようなバインドは持続的です。PSK セッションでは、非対称鍵による認証が行われないため、空の鍵名が報告されます。

### TPM リセットピン制御

SPDM の有効化/無効化および SPDM 専用モードの変更を反映するには、TPM のリセットが必要です。ホストから制御可能なリセットピンを使うのが最も簡単ですが、TPM の電源レールをサイクルさせる方法でも可能です。

!!! warning
    カスタムハードウェア設計では、TPM のリセットピンをホストが制御できる GPIO に配線するか、TPM の電源レールを切り替え可能にしてください。TPM をリセットまたは電源サイクルする手段がない場合、SPDM モードの変更を適用できず、SPDM 専用モードからの回復もできません。

リセットラインはボードごとに異なります。Raspberry Pi では、Nuvoton は GPIO4 を、ST33KTPM は GPIO24 (ピン 18) を使用します。テスト済みの NS350 ドーターボードでも GPIO4 が TPM_RST に配線されています。切り替える前に配線を確認してください。

libgpiod 1.x では、`gpioset` はラインを設定して終了します。`spdm_test.sh` はこの動作に依存しています (チップは位置引数です)。

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

libgpiod 2.x では、チップは `--chip` で指定し、`gpioset` はプロセスが終了するまでラインを保持するため、単純な `&&` の連鎖では解放ステップに到達しません。ラインにパルスを与える方法の一例を示します。

```sh
timeout 0.1 gpioset --chip gpiochip0 4=0
gpioset --chip gpiochip0 --daemonize 4=1
sleep 2
```

上記の 2.x 形式は、1.x の構文を使用するテストハーネスに対しては実行していません。`gpioset` の終了後、libgpiod はラインの状態を保証しないため、リセットラインにプルアップがあることを確認してください。ST33 の場合は、4 の代わりにライン 24 を使用します。繰り返し可能な自動化には、wolfTPM のリセット HAL を使用することを推奨します。

wolfTPM は、コードからリセットを駆動することもできます。`--enable-hal-reset` を付けてビルドし、`TPM2_IoCb_Reset(ctx, userCtx)` を呼び出します。この関数は `TPM2_CTX*` と `void*` を受け取ります。デフォルトのラインは、ST33 が GPIO24、Nuvoton が GPIO4 です。Nations のビルドも、ライン 4 を明示的に指定しない限り、デフォルトは GPIO24 です。ソースツリーの `hal/README.md` を参照してください。

## TCG SPDM ベンダーコマンド

Nuvoton と Nations の TPM は、どちらも TCG の "TPM Communication over SPDM Secure Session" バインディングを実装しています。このバインディングは、各メッセージを SPDM の `VENDOR_DEFINED_REQUEST` (リクエストコード `0xFE`) として運び、`VENDOR_DEFINED_RESPONSE` (レスポンスコード `0x7E`) で応答します。`StandardID=0x0001` (TCG) が使用されます。メッセージ内のベンダーコード (VdCode) は 8 バイトの ASCII 文字列です。

公開されている TCG の表では、`GET_PUBK`、`GIVE_PUB`、`TPM2_CMD`、および任意のロカリティ固有の `TPM2CMD0` から `TPM2CMD4` までの値が定義されています。`GET_STS_`、`SPDMONLY`、`PSK_SET_`、`PSK_CLR_` は実装またはベンダーによる拡張であり、TCG が定義したコマンドではありません。2 つのベンダーアダプターにおけるベンダー拡張の正確なワイヤ形式の詳細は wolfSPDM サブモジュール内にありますが、このページのレビューに使用したツリーには存在しませんでした。

| VdCode | コマンド | 定義元 | ベンダー | 説明 |
|--------|---------|------------|--------|-------------|
| `GET_PUBK` | Get Public Key | TCG | 両方 | TPM の SPDM-Identity P-384 公開鍵を取得 |
| `GIVE_PUB` | Give Public Key | TCG | 両方 | ホストの P-384 公開鍵を TPM に送信 |
| `TPM2_CMD` | TPM Command | TCG | 両方 | TPM コマンドを SPDM セキュアメッセージでラップ |
| `GET_STS_` | Get Status | ベンダー拡張 | 両方 | SPDM の状態を照会 |
| `SPDMONLY` | SPDM-Only Mode | ベンダー拡張 | 両方 | SPDM 専用の強制をロック/ロック解除 |
| `PSK_SET_` | PSK Set | ベンダー拡張 | Nations | 事前共有鍵をプロビジョニング (64 バイトの PSK + SHA-384 ダイジェスト) |
| `PSK_CLR_` | PSK Clear | ベンダー拡張 | Nations | プロビジョニング済みの PSK をクリア (ClearAuth が必要) |

## ベンダー固有の事項

### Nuvoton NPCT75x

- 有効化/無効化: SPDM は `NTC2_PreConfig` ベンダーコマンド (`--enable` / `--disable`) で有効化されます。これはリセットをまたいで永続します。
- GPIO リセット: Nuvoton のドーターボードでは GPIO 4 が TPM_RST に配線されています。GPIO リセットにより、残存している SPDM 状態がクリアされます。コマンドについては TPM リセットピン制御を参照してください。

### Nations NS350

- モード切り替え: アイデンティティ鍵モードと PSK モードは排他的です。アイデンティティ鍵は工場出荷時にプロビジョニングされています。PSK をプロビジョニングする前に `--identity-key-unset` を使用し、復元するには `--identity-key-set` を使用します。
- リセット: ハードウェアでテスト済みのハーネス (`spdm_test.sh`) は、NS350 のドーターボードでは GPIO 4 が TPM_RST に配線されているものとして扱い、Nations の状態を正規化する際にこれを使用します。アイデンティティ鍵と PSK は NV に保存され、リセット後も保持されます。お使いのボードでこのラインが配線されていない場合は、完全な電源の入れ直しが必要です。`sudo reboot` では 3.3V レールが通電したままであるためです。
- ケイパビリティの照会: SPDM セッション情報を含む TPM 184 ベンダープロパティを照会するには、`--caps184` を使用します。
- ClearAuth: 正確に 32 バイトでなければなりません。`PSK_SET` はその SHA-384 ダイジェスト (48 バイト) を保存します。`PSK_CLEAR` は生の 32 バイトを送信し、TPM が検証のために SHA-384 を計算します。

!!! note
    一部の NS350 ファームウェアバージョンでは、鍵が存在していても `--status` が "Identity Key: not provisioned" と報告することがあります。決定的なテストは `--connect` コマンドです。ECDHE ハンドシェイクが成功すれば、アイデンティティ鍵はプロビジョニングされています。

PSK ベンダーエラーコードは、Nations の統合ガイドに記載されているとおりです。これらはベンダー拡張であり、本プロジェクトでは、Nations の公開資料やソースツリーに照らして値を確認できませんでした。お使いのファームウェアのドキュメントで確認してください。

| コード | 名前 | 説明 |
|------|------|-------------|
| 0xA1 | Vd_PSKAlreadySet | PSK はすでにプロビジョニング済み (先に PSK_CLEAR が必要) |
| 0xA2 | Vd_InternalFailure | SPDM セッション層の内部エラー |
| 0xA3 | Vd_PSKNotSet | PSK がプロビジョニングされていない |
| 0xA5 | Vd_AuthFail | ClearAuth の SHA-384 が保存されたダイジェストと一致しない |

### Auto-SPDM

アイデンティティモードでは信頼できるレスポンダー鍵を指定して `wolfTPM2_InitWithSpdmKey()` を、PSK モードではプロビジョニング済みの PSK を指定して `wolfTPM2_InitWithSpdmPsk()` を呼び出します。どちらのエントリーポイントも、すでに SPDM 専用モードでロックされている TPM から回復します。アイデンティティモードの初期化手順は次のとおりです。

1. `TPM2_Startup` が、TPM がすでに SPDM 専用モードであるかどうかを調べます。
2. 呼び出し側が提供したレスポンダー鍵が、トラストアンカーとしてインストールされます。
3. 検出されたレスポンダー鍵が、その信頼された鍵と比較されます。
4. SPDM セッションが常に確立されます (P-384 鍵生成とハンドシェイク)。
5. プローブが `TPM_RC_DISABLED` を返した場合、`TPM2_Startup` が安全にリトライされます。
6. 以降のすべてのコマンドは、SPDM の暗号化チャネルを通ります。

デュアルベンダービルドでは、`wolfTPM2_InitWithSpdmKey()` は TPM の DID/VID からアイデンティティアダプターを選択します。DID/VID を公開しないトランスポートでは、`WOLFSPDM_MODE_NUVOTON` または `WOLFSPDM_MODE_NATIONS` を指定して `wolfTPM2_InitWithSpdmKey_ex()` を呼び出す必要があります。自動モードは、推測せずにフェイルクローズします。

資格情報なしの `wolfTPM2_Init()` は、いずれかの SPDM 専用モードを検出するとフェイルクローズします。即時のセキュアチャネルを必要としない通常モードの TPM では、アイデンティティモードのアプリケーションは代わりに `wolfTPM2_SpdmInit()`、`wolfTPM2_SpdmSetResponderPubKey()`、続いてベンダー固有の接続関数を呼び出すことができます。

`TPM2_SendCommand` (認証なしのコマンド) と `TPM2_SendCommandAuth` (PCR 操作、鍵作成、署名などの認証セッション付きコマンド) の両方が、セッションがアクティブな場合にインターセプトされ、SPDM 経由でルーティングされます。

### メモリモード

- デフォルト: ヒープ割り当てなし。SPDM コンテキストは約 32 KB の、呼び出し側が所有するインラインコンテキストです。必ずしも静的記憶域期間のストレージではなく、呼び出し側が配置した場所に存在します。
- スモールスタック (`--enable-smallstack`): コンテキストとコマンドごとのメッセージバッファは `XMALLOC` で確保されます。スタックが小さいプラットフォームで有用です。

`wolfSPDM_New()` は、wolfSPDM が `WOLFSPDM_DYNAMIC_MEMORY` 付きでビルドされた場合にのみ存在します。それ以外の場合は、呼び出し側が提供するストレージに対して `wolfSPDM_InitStatic()` または `wolfSPDM_Init()` を使用してください。

## wolfSPDM API

| 関数 | 説明 |
|----------|-------------|
| `wolfSPDM_InitStatic()` | 呼び出し側が提供するバッファ内でコンテキストを初期化 (静的モード) |
| `wolfSPDM_New()` | ヒープ上にコンテキストを確保して初期化 (`WOLFSPDM_DYNAMIC_MEMORY` の場合のみ) |
| `wolfSPDM_Init()` | 事前に確保されたコンテキストを初期化 |
| `wolfSPDM_Free()` | コンテキストを解放 (リソースを解放し、動的な場合のみヒープを解放) |
| `wolfSPDM_GetCtxSize()` | 実行時に `sizeof(WOLFSPDM_CTX)` を返す |
| `wolfSPDM_SetIO()` | トランスポート I/O コールバックを設定 |
| `wolfSPDM_SetResponderPubKey()` | 信頼できるレスポンダーの P-384 鍵を固定 (アイデンティティモード) |
| `wolfSPDM_SetPSK()` | 事前共有鍵を設定 (PSK モード) |
| `wolfSPDM_SetMode()` | ベンダー/ハンドシェイクモードを選択 |
| `wolfSPDM_SetRequesterKeyPair()` | GIVE_PUB と FINISH に使用するホストの P-384 鍵ペアを設定 |
| `wolfSPDM_SetDebug()` | デバッグ出力の有効化/無効化 |
| `wolfSPDM_Connect()` | SPDM ハンドシェイク全体 |
| `wolfSPDM_IsConnected()` | セッション状態を確認 |
| `wolfSPDM_Disconnect()` | セッションを終了 |
| `wolfSPDM_SecuredExchange()` | 暗号化/送信/受信/復号を 1 回の呼び出しで実行 |

## トラブルシューティング

### セッションの中断後にハンドシェイクが失敗する

TPM 上に SPDM の状態が残っていると、次のハンドシェイクが失敗することがあります。TPM をリセットしてください。

- Nuvoton: Nuvoton のドーターボードでは GPIO 4 が TPM_RST に配線されているため、GPIO リセットで状態がクリアされます。コマンドについては TPM リセットピン制御を参照してください。
- Nations NS350: テスト済みのドーターボードでも GPIO 4 が TPM_RST に配線されているため、同じ GPIO リセットが適用されます。お使いのボードで配線されていない場合は、完全な電源の入れ直しを行ってください。3.3V レールが通電したままであるため、`sudo reboot` では不十分です。

### SPDM エラーコード

| コード | 名前 | 説明 |
|------|------|-------------|
| 0x01 | InvalidRequest | メッセージ形式が不正 |
| 0x04 | UnexpectedRequest | メッセージの順序が不正 |
| 0x05 | Unspecified | 未指定のエラー |
| 0x06 | DecryptError | 復号または MAC 検証に失敗 |
| 0x07 | UnsupportedRequest | リクエストが未サポート、または形式が拒否された |
| 0x41 | MajorVersionMismatch | SPDM のメジャーバージョンの不一致 |

## 標準 SPDM のサポート

ツリー内の TPM プロファイルがカバーするのは、TCG SPDM バインディングのみです。DMTF の spdm-emu エミュレーターとのセッション、測定 (measurements)、チャレンジ認証、ハートビート、鍵更新を含む標準 SPDM プロトコルのサポートには、スタンドアロンの [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) ライブラリを使用してください。これらの機能は wolfTPM の対象外です。

## 自動テスト

`spdm_test.sh` は、SPDM のセットアップライフサイクル全体を実行します。

```sh
# Nuvoton (identity key, includes GPIO resets between tests)
SPDM_RESPONDER_PUBKEY="$(cat responder_pubkey.hex)"
export SPDM_RESPONDER_PUBKEY
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton

# Nations (identity key; the harness also uses GPIO 4 to normalize state)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations

# Nations (PSK, full lifecycle: provision, connect, clear, restore)
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nations-psk
```

アイデンティティモードのハードウェアでの実行には、信頼できるプロビジョニング元 (デバイスのプロビジョニング記録) から得た `SPDM_RESPONDER_PUBKEY` が必要です。PSK の実行ではこれを使用しません。一方、`fwtpm-tcg` テストは、テストハーネスが作成したオーナー専用のサーバーログから新しく生成された公開鍵を読み取り、同じ固定用インターフェースを通じて渡します。このローカルでのブートストラップは、ハードウェアのプロビジョニング手段ではありません。

SPDM をサポートするハードウェア TPM の本番利用については、support@wolfssl.com までお問い合わせください。

## 関連項目

- [fwtpm/spdm.md](fwtpm/spdm.md)
- [post-quantum.md](post-quantum.md)
- [FWTPM.md](fwtpm/overview.md)
- [DEVTPM.md](system-interfaces.md)
