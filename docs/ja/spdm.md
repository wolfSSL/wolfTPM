# SPDM アテステーションとセキュアセッション

wolfTPM には、wolfSSL/wolfCrypt を使用した、Nuvoton NPCT75x および Nations NS350 TPM 向けの SPDM (Security Protocol and Data Model、DMTF DSP0274) サポートが組み込まれています。SPDM は、TCG の SPDM-over-TPM バインディング上でプロトコルバージョン 1.3 をネゴシエートします。両ベンダーとも、セッション確立のためのアイデンティティ鍵モード (ECDHE P-384) をサポートしています。Nations NS350 は、さらに PSK (事前共有鍵) モードもサポートしています。セッションが確立されると、すべての TPM コマンドとレスポンスは、既存の SPI または I2C バス上で AES-256-GCM により暗号化されます。アイデンティティ鍵モードでは、信頼できるプロビジョニング元から得たレスポンダーの P-384 公開鍵が必要です。

SPDM のコードは [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) ライブラリにあり、`lib/wolfSPDM` サブモジュールとして含まれ、TPM プロファイルで libwolftpm にコンパイルされます。SPDM を使用する wolfTPM のチェックアウトは、必ず `--recursive` 付きでクローンしてください。サブモジュールがない場合、`./configure --enable-spdm` は次のメッセージで停止します: `--enable-spdm needs the wolfSPDM submodule: run git submodule update --init lib/wolfSPDM`。

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

# Enable SPDM (one-time), reset, connect
./examples/spdm/spdm_ctrl --enable
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
./examples/spdm/spdm_ctrl --responder-pubkey <trusted_p384_x_y_hex> --connect
```

### Nations NS350

```sh
# Build wolfSSL (in the sibling checkout, then return here)
cd ../wolfssl && ./autogen.sh && \
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp && \
make && sudo make install && sudo ldconfig && cd -

# Build wolfTPM (submodule already present from the recursive clone)
./autogen.sh && ./configure --enable-spdm --enable-nations && make

# Connect (identity key is factory default)
./examples/spdm/spdm_ctrl --responder-pubkey <trusted_p384_x_y_hex> --connect
```

## 概要と動作の仕組み

`spdm_ctrl` ツールは、ホストと TPM の間に SPI 経由で SPDM セキュアセッションを確立し、AES-256-GCM で暗号化されたバス通信を可能にします。実装は Algorithm Set B (ECDH P-384、SHA-384、AES-256-GCM) を使用します。セッション確立モードは 2 つサポートされています。

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
  |--- GET_PUB_KEY ------------------>|  (get TPM's P-384 identity key)
  |<-- PUB_KEY_RSP -------------------|
  |                                   |
  |--- KEY_EXCHANGE ----------------->|  (ECDHE P-384 key agreement)
  |<-- KEY_EXCHANGE_RSP --------------|  (+ HMAC proof of shared secret)
  |                                   |
  |    --- Handshake keys derived --- |
  |                                   |
  |=== GIVE_PUB_KEY =================>|  (encrypted: host's P-384 key)
  |<== GIVE_PUB_KEY_RSP ==============|
  |                                   |
  |=== FINISH =======================>|  (encrypted: signature + HMAC)
  |<== FINISH_RSP ====================|
  |                                   |
  |    --- App data keys derived ---  |
  |                                   |
  |=== TPM2_CMD (AES-256-GCM) =======>|  (every command encrypted)
  |<== TPM2_RSP (AES-256-GCM) ========|
```

ハンドシェイクでは、鍵合意に ECDH P-384 を、認証に HMAC-SHA384 を使用します。ハンドシェイク後、すべての TPM コマンドは SPDM の `VENDOR_DEFINED_REQUEST("TPM2_CMD")` メッセージでラップされ、AES-256-GCM で暗号化されます。リプレイ攻撃を防ぐため、メッセージごとにシーケンス番号がインクリメントされます。

### PSK モード (Nations のみ)

PSK モードは、ECDHE 鍵交換を対称の事前共有鍵に置き換えます。データ転送には同じ AES-256-GCM 暗号化が使用されます。

```
Host                                TPM (Nations NS350)
  |                                   |
  |--- GET_VERSION ------------------>| (negotiate SPDM version)
  |<-- VERSION -----------------------|
  |                                   |
  |--- GET_CAPABILITIES ------------->| (capability exchange)
  |<-- CAPABILITIES ------------------|
  |                                   |
  |--- NEGOTIATE_ALGORITHMS --------->| (Algorithm Set B: P-384/SHA-384)
  |<-- ALGORITHMS --------------------|
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

NS350 では、PSK モードとアイデンティティ鍵モードは排他的です。アイデンティティ鍵は工場出荷時にプロビジョニングされており、PSK を使用する前に解除する必要があります。[PSK ライフサイクル](#psk-ライフサイクル-nations)を参照してください。

### SPDM 専用モード (暗号化バスの強制)

SPDM 専用モードは、すべての TPM コマンドを暗号化された SPDM チャネル経由に強制します。両ベンダーがサポートしています。典型的なライフサイクルは次のとおりです。

```
1. Enable SPDM        (one-time, persists across resets)
2. Connect            (handshake, derives session keys)
3. Lock SPDM-only     (TPM rejects all cleartext commands)
4. Reset              (TPM enters SPDM-only enforcement)
5. Initialize with the trusted key or PSK and run commands (all encrypted)
6. Unlock             (connect + unlock in one session)
7. Reset              (TPM back to normal cleartext mode)
```

アプリケーションが `wolfTPM2_InitWithSpdmKey()` を通じてレスポンダー鍵を提供した後、wolfTPM は平文での起動結果にかかわらず、レスポンダーを認証して暗号化セッションを確立します。詳細は [Auto-SPDM](#auto-spdm) を参照してください。

リセット方法はベンダーによって異なります。

- Nuvoton: GPIO リセット、`gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2`
- Nations: 完全な電源の入れ直しが必要です (NS350 のドーターボードでは GPIO 4 が TPM_RST に配線されていません)

## ビルド

### 1. wolfSPDM サブモジュールを含めてクローンする

[クイックスタート](#クイックスタート)を参照してください。SPDM は `lib/wolfSPDM` サブモジュールからビルドされるため、wolfTPM を再帰的にクローンするか、既存のチェックアウトで `git submodule update --init lib/wolfSPDM` を実行してください。

### 2. wolfSSL

Nuvoton と Nations は同じ wolfSSL フラグを使用します。これらは SPDM Algorithm Set B のための暗号処理を提供します。

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

`--enable-spdm` に加えて、少なくとも 1 つのハンドシェイクモードを指定してビルドします。証明書ハンドシェイクには `--enable-tcg`、PSK ハンドシェイクには `--enable-psk` です。ベンダー固有のワイヤフォーマットアダプター (`--enable-nuvoton`、`--enable-nations`) は任意です。

### wolfTPM の SPDM プロファイル

`--enable-spdm` は `WOLFTPM_SPDM` を定義し、これにより wolfSPDM の `WOLFSPDM_PROFILE_TPM` が自動的に選択されます。TPM は TCG SPDM Binding のみを話すため、このプロファイルは TCG に特化した軽量ビルドです。次のものは自動的にコンパイルから除外されます。

- DMTF 標準のリクエスター: `GET_CAPABILITIES`、`NEGOTIATE_ALGORITHMS`、`GET_DIGESTS`、`GET_CERTIFICATE`、および証明書チェーンの検証
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
| `--enable-smallstack` | ヒープに確保される SPDM コンテキスト (デフォルト: 静的、約 32 KB) |

`configure` は、次の互換性のない組み合わせを拒否します。

- `--enable-nuvoton --disable-tcg` (Nuvoton は TCG SPDM Binding を使用します)
- `--enable-nations --disable-tcg` または `--enable-nations --disable-psk`
- `--enable-psk --disable-tcg` (PSK は TCG のフレーミング上で動作します)

### fwTPM SPDM レスポンダー (シリコン不要)

`fwtpm_server` には SPDM 1.3 レスポンダーが含まれており、実際の Nuvoton および Nations のデバイスが使用するのと同じハンドシェイクを駆動します。これにより、実ハードウェアなしで CI 上で TCG と PSK のスタック全体を検証できます。

```sh
./src/fwtpm/fwtpm_server --spdm-tcg          # TCG cert handshake
./src/fwtpm/fwtpm_server --spdm-psk \
    --spdm-psk-hex dbc2192291d807742441b963f6712841...   # PSK handshake
```

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
    --responder-pubkey <trusted_p384_x_y_hex> --connect
./examples/spdm/spdm_ctrl --vendor=nations \
    --responder-pubkey <trusted_p384_x_y_hex> --connect
```

単一ベンダーのビルドは、バイナリにコンパイルされたアダプターのみを受け付け、利用できない `--vendor=` の値を拒否します。

## 使い方と制御コマンド

### 初回セットアップ

Nuvoton:

```sh
# Enable SPDM on the TPM (persists across resets)
./examples/spdm/spdm_ctrl --enable

# GPIO reset
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

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
# Establish SPDM session (VERSION, GET_PUBK, KEY_EXCHANGE, GIVE_PUB, FINISH)
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect

# Query SPDM status
./examples/spdm/spdm_ctrl --status
```

`--responder-pubkey` は、信頼できる生の P-384 X||Y 点を 192 文字の 16 進数で受け取ります。デバイスのプロビジョニング記録、または認証されたその他の製造元チャネルから入手してください。

!!! warning
    `--get-pubkey` は認証なしの探索であり、それ単体で信頼を確立するために使用してはいけません。

PSK モード (Nations) では、先に PSK をプロビジョニングする必要があります。[PSK ライフサイクル](#psk-ライフサイクル-nations)を参照してください。

```sh
# Establish PSK session (VERSION, CAPS, ALGO, PSK_EXCHANGE, PSK_FINISH)
./examples/spdm/spdm_ctrl --psk <psk_hex_128chars>
```

### SPDM 専用モードのロックとロック解除

ロックにはアクティブな SPDM セッションが必要です。ロック後、強制を有効にするにはリセットが必要です。

Nuvoton (アイデンティティ鍵):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2

# Unlock
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

Nations (アイデンティティ鍵):

```sh
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
# Power cycle required (unplug and re-plug Raspberry Pi)

./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
# Power cycle again
```

Nations (PSK モード):

```sh
./examples/spdm/spdm_ctrl --psk <hex> --lock
# Power cycle required

./examples/spdm/spdm_ctrl --psk <hex> --unlock
# Power cycle again
```

### PSK ライフサイクル (Nations)

NS350 では、PSK モードとアイデンティティ鍵モードは排他的です。アイデンティティ鍵はデフォルトでプロビジョニングされており、PSK を使用する前に解除する必要があります。

```sh
# 1. Unset identity key (enables PSK mode)
./examples/spdm/spdm_ctrl --identity-key-unset

# 2. Provision PSK (64-byte PSK + 32-byte ClearAuth)
#    The demo computes SHA-384(ClearAuth) and sends PSK(64)+Digest(48) = 112 bytes
./examples/spdm/spdm_ctrl --psk-set <psk_hex_128chars> <clearauth_hex_64chars>

# 3. Establish PSK session
./examples/spdm/spdm_ctrl --psk <psk_hex_128chars>

# 4. Clear PSK (sends raw 32-byte ClearAuth; TPM verifies SHA-384 internally)
./examples/spdm/spdm_ctrl --psk-clear <clearauth_hex_64chars>

# 5. Restore identity key (factory default)
./examples/spdm/spdm_ctrl --identity-key-set
```

!!! warning
    ClearAuth は正確に 32 バイトでなければなりません。PSK_SET はその SHA-384 ダイジェスト (48 バイト) を保存します。PSK_CLEAR は生の 32 バイトを送信し、TPM が検証のために SHA-384 を計算します。サイズを誤ると PSK_CLEAR が実行不可能になります。

### コマンドリファレンス

`spdm_ctrl` のすべてのオプション:

| オプション | ベンダー | 説明 |
|--------|--------|-------------|
| `--enable` | Nuvoton | NTC2_PreConfig 経由で SPDM を有効化 (一度だけ、永続、リセットが必要) |
| `--disable` | Nuvoton | NTC2_PreConfig 経由で SPDM を無効化 (リセットが必要) |
| `--identity-key-set` | Nations | SPDM アイデンティティ鍵をプロビジョニング (工場出荷時のデフォルト) |
| `--identity-key-unset` | Nations | アイデンティティ鍵のプロビジョニングを解除 (PSK の前に必要) |
| `--vendor=nuvoton\|nations` | 両方 | アイデンティティ/ベンダーアダプターを明示的に選択 |
| `--get-pubkey` | 両方 | 認証せずに TPM のアイデンティティ鍵を探索 |
| `--responder-pubkey <hex>` | 両方 | 信頼できる生の P-384 X\|\|Y レスポンダー鍵を固定 (192 文字の 16 進数) |
| `--connect` | 両方 | アイデンティティ鍵 SPDM セッションを確立 (ECDH P-384 ハンドシェイク) |
| `--caps` | 両方 | 現在のトランスポート経由で TPM のケイパビリティを読み取る |
| `--status` | 両方 | SPDM の状態を照会 |
| `--session-info` | 両方 | TPM から見た SPDM セッションを表示 (`TPM_CAP_SPDM_SESSION_INFO`) |
| `--policy-nv` | 両方 | `TPM2_PolicyTransportSPDM` で保護された NV インデックスを定義し、セッション経由で書き込みと読み取りを行う |
| `--lock` | 両方 | SPDM 専用モードをロック (`--connect` と併用、アクティブなセッションが必要) |
| `--unlock` | 両方 | SPDM 専用モードのロックを解除 (`--connect` と併用、アクティブなセッションが必要) |
| `--psk <psk>` | Nations | PSK セッションを確立 (64 バイトの PSK) |
| `--psk-set <psk> <clearauth>` | Nations | PSK をプロビジョニング (64 バイトの PSK、32 バイトの ClearAuth) |
| `--psk-clear <clearauth>` | Nations | PSK をクリア (32 バイトの ClearAuth) |
| `--caps184` | Nations | TPM 184 ベンダープロパティと SPDM セッション情報を照会 |
| `--tpm-clear` | Nations | 現在のトランスポート経由で `TPM2_Clear` を送信 (プラットフォーム auth) |

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
    --vendor=nuvoton --responder-pubkey <trusted_p384_x_y_hex> --connect

# Lock SPDM-only mode (connect + lock in one session)
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --lock
# Reset the TPM

# Unlock SPDM-only mode
# Reset the TPM
./examples/spdm/spdm_ctrl \
    --responder-pubkey <trusted_p384_x_y_hex> --connect --unlock
# Reset the TPM
```

### nv_bind

`nv_bind` サンプルは、`--policy-nv` の考え方に焦点を当てた、自己完結型のバージョンです。`authPolicy` が `TPM2_PolicyTransportSPDM` である NV インデックスをプロビジョニングし、SPDM-PSK セッション経由でシークレットを保存したうえで、通常の (SPDM ではない) 接続経由での同一の読み取りが `TPM_RC_CHANNEL` で拒否されることを示します。

```sh
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex <psk> --clear &
./examples/spdm/nv_bind --psk <psk>
```

fwTPM は起動のたびに新しい SPDM アイデンティティ鍵を生成するため、fwTPM 上では `tpmKeyName` にバインドされたポリシーはそのサーバーの存続期間中のみ有効です。ハードウェア TPM は永続的なアイデンティティ鍵を保持しているため、そのようなバインドは持続的です。PSK セッションでは、非対称鍵による認証が行われないため、空の鍵名が報告されます。

### TPM リセットピン制御

SPDM の有効化/無効化および SPDM 専用モードの変更を反映するには、TPM のリセットが必要です。リセットピンは接続されており、ホストから制御可能である必要があります。

!!! warning
    カスタムハードウェア設計では、TPM のリセットピンをホストが制御できる GPIO に配線してください。リセットピンを制御できない場合、SPDM モードの変更を適用できず、SPDM 専用モードからの回復もできません。

リセットラインはボードごとに異なります。Raspberry Pi では、Nuvoton は GPIO4 を、ST33KTPM は GPIO24 (ピン 18) を使用します。切り替える前に配線を確認してください。

```sh
# Assert reset low, release high, wait for TPM startup (Nuvoton GPIO4 shown)
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
# ST33: use line 24 instead of 4
```

wolfTPM は、コードからこれを駆動することもできます。`--enable-hal-reset` を付けてビルドし、`TPM2_IoCb_Reset()` を呼び出します (デフォルトのライン: ST33 は GPIO24、Nuvoton は GPIO4)。ソースツリーの `hal/README.md` を参照してください。

## TCG SPDM ベンダーコマンド

Nuvoton と Nations の TPM は、どちらも TCG の "TPM Communication over SPDM Secure Session" 仕様を実装しています。これらのコマンドは、`StandardID=0x0001` (TCG) の SPDM `VENDOR_DEFINED_REQUEST` メッセージ内で、8 バイトの ASCII ベンダーコードを使用します。

| VdCode | コマンド | ベンダー | 説明 |
|--------|---------|--------|-------------|
| `GET_PUBK` | Get Public Key | 両方 | TPM の SPDM-Identity P-384 公開鍵を取得 |
| `GIVE_PUB` | Give Public Key | 両方 | ホストの P-384 公開鍵を TPM に送信 |
| `TPM2_CMD` | TPM Command | 両方 | TPM コマンドを SPDM セキュアメッセージでラップ |
| `GET_STS_` | Get Status | 両方 | SPDM の状態を照会 |
| `SPDMONLY` | SPDM-Only Mode | 両方 | SPDM 専用の強制をロック/ロック解除 |
| `PSK_SET_` | PSK Set | Nations | 事前共有鍵をプロビジョニング (64 バイトの PSK + SHA-384 ダイジェスト) |
| `PSK_CLR_` | PSK Clear | Nations | プロビジョニング済みの PSK をクリア (ClearAuth が必要) |

## ベンダー固有の事項

### Nuvoton NPCT75x

- 有効化/無効化: SPDM は `NTC2_PreConfig` ベンダーコマンド (`--enable` / `--disable`) で有効化されます。これはリセットをまたいで永続します。
- GPIO リセット: Nuvoton のドーターボードでは GPIO 4 が TPM_RST に配線されています。GPIO リセットにより、残存している SPDM 状態がクリアされます。

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

### Nations NS350

- モード切り替え: アイデンティティ鍵モードと PSK モードは排他的です。アイデンティティ鍵は工場出荷時にプロビジョニングされています。PSK をプロビジョニングする前に `--identity-key-unset` を使用し、復元するには `--identity-key-set` を使用します。
- GPIO リセットなし: NS350 のドーターボードでは GPIO 4 は TPM_RST に配線されていません。TPM をリセットするには、完全な電源の入れ直し (Raspberry Pi の電源を抜いて再接続) が必要です。3.3V レールが通電したままであるため、`sudo reboot` では不十分です。
- ケイパビリティの照会: SPDM セッション情報を含む TPM 184 ベンダープロパティを照会するには、`--caps184` を使用します。
- ClearAuth: 正確に 32 バイトでなければなりません。`PSK_SET` はその SHA-384 ダイジェスト (48 バイト) を保存します。`PSK_CLEAR` は生の 32 バイトを送信し、TPM が検証のために SHA-384 を計算します。

!!! note
    一部の NS350 ファームウェアバージョンでは、鍵が存在していても `--status` が "Identity Key: not provisioned" と報告することがあります。決定的なテストは `--connect` コマンドです。ECDHE ハンドシェイクが成功すれば、アイデンティティ鍵はプロビジョニングされています。

PSK ベンダーエラーコード:

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

- 静的 (デフォルト): ヒープ割り当てなし。SPDM コンテキストは約 32 KB の静的メモリを使用し、組み込み環境に適しています。
- スモールスタック (`--enable-smallstack`): コンテキストはヒープに確保されます。スタックが小さいプラットフォームで有用です。

## wolfSPDM API

| 関数 | 説明 |
|----------|-------------|
| `wolfSPDM_InitStatic()` | 呼び出し側が提供するバッファ内でコンテキストを初期化 (静的モード) |
| `wolfSPDM_New()` | ヒープ上にコンテキストを確保して初期化 (動的モード) |
| `wolfSPDM_Init()` | 事前に確保されたコンテキストを初期化 |
| `wolfSPDM_Free()` | コンテキストを解放 (リソースを解放し、動的な場合のみヒープを解放) |
| `wolfSPDM_GetCtxSize()` | 実行時に `sizeof(WOLFSPDM_CTX)` を返す |
| `wolfSPDM_SetIO()` | トランスポート I/O コールバックを設定 |
| `wolfSPDM_SetResponderPubKey()` | 信頼できるレスポンダーの P-384 鍵を固定 |
| `wolfSPDM_SetDebug()` | デバッグ出力の有効化/無効化 |
| `wolfSPDM_Connect()` | SPDM ハンドシェイク全体 |
| `wolfSPDM_IsConnected()` | セッション状態を確認 |
| `wolfSPDM_Disconnect()` | セッションを終了 |
| `wolfSPDM_SecuredExchange()` | 暗号化/送信/受信/復号を 1 回の呼び出しで実行 |

## トラブルシューティング

### セッションの中断後にハンドシェイクが失敗する

TPM 上に SPDM の状態が残っていると、次のハンドシェイクが失敗することがあります。TPM をリセットしてください。

- Nuvoton: Nuvoton のドーターボードでは GPIO 4 が TPM_RST に配線されているため、GPIO リセットで状態がクリアされます。

```sh
gpioset gpiochip0 4=0 && sleep 0.1 && gpioset gpiochip0 4=1 && sleep 2
```

- Nations NS350: NS350 のドーターボードでは GPIO 4 は TPM_RST に配線されていません。完全な電源の入れ直し (Raspberry Pi の電源を抜いて再接続) が必要です。3.3V レールが通電したままであるため、`sudo reboot` では不十分です。

### SPDM エラーコード

| コード | 名前 | 説明 |
|------|------|-------------|
| 0x01 | InvalidRequest | メッセージ形式が不正 |
| 0x04 | UnexpectedRequest | メッセージの順序が不正 |
| 0x05 | DecryptError | 復号または MAC 検証に失敗 |
| 0x06 | UnsupportedRequest | リクエストが未サポート、または形式が拒否された |
| 0x41 | VersionMismatch | SPDM バージョンの不一致 |

## 標準 SPDM のサポート

ツリー内の TPM プロファイルがカバーするのは、TCG SPDM バインディングのみです。DMTF の spdm-emu エミュレーターとのセッション、測定 (measurements)、チャレンジ認証、ハートビート、鍵更新を含む標準 SPDM プロトコルのサポートには、スタンドアロンの [wolfSPDM](https://github.com/wolfSSL/wolfSPDM) ライブラリを使用してください。これらの機能は wolfTPM の対象外です。

## 自動テスト

`spdm_test.sh` は、SPDM のセットアップライフサイクル全体を実行します。

```sh
# Nuvoton (identity key, includes GPIO resets between tests)
export SPDM_RESPONDER_PUBKEY=<trusted_p384_x_y_hex>
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl nuvoton

# Nations (identity key, no GPIO resets)
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
