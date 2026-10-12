# Rust ラッパー

`wolftpm` クレートは、wolfTPM 向けの安全な Rust バインディングを提供します。生の FFI は bindgen で生成され、`sys` モジュールに格納されています。クレートのそれ以外の部分は安全な API です。関数は `Result` を返し、TPM ハンドルはスコープを外れると解放され、すべての `unsafe` はクレート内部に閉じ込められています。このクレートは wolfTPM のソースツリー内の `wrapper/rust/wolftpm` にあります。

## 要件

- Rust と Cargo (stable、rustc 1.81 以降)。
- ビルド済みの wolfTPM C ライブラリ (`libwolftpm`) とその依存先である wolfSSL (`libwolfssl`)。このクレートはビルド済みライブラリをリンクします。C コード自体はビルドしません。
- テストにはソフトウェア TPM が必要です。wolfTPM 独自の `fwtpm_server`、または他の TPM エミュレータやソフトウェア TPM を使用できます。[fwTPM](fwtpm/overview.md) と [SWTPM](system-interfaces.md) を参照してください。

## ステップ 1: C ライブラリをビルドする

wolfTPM リポジトリのルートで次を実行します。

```sh
./autogen.sh
./configure --enable-swtpm --enable-fwtpm
make
```

これにより `src/.libs/libwolftpm` が生成されます。`--enable-fwtpm` を指定すると、ソフトウェア TPM サーバー `src/fwtpm/fwtpm_server` もビルドされます。

## ステップ 2: クレートをビルドする

```sh
cd wrapper/rust/wolftpm
cargo build
```

ビルドは次の順序でライブラリを探します。

1. `WOLFTPM_PREFIX` または `WOLFSSL_PREFIX` が設定されている場合は、インストール済みコピーの `$PREFIX/include` と `$PREFIX/lib` を使用します。
2. それ以外の場合はツリー内のビルドを使用します。ヘッダーはリポジトリのルートから、ライブラリは `src/.libs` から取得します。wolfSSL は `pkg-config`、次にローカルの `./wolfssl`、あるいは隣接する `../wolfssl` チェックアウトの順に探されます。

共有ライブラリが優先されます。共有ライブラリが存在しない場合は静的ライブラリが使用されます。

このライブラリは `no_std` であり、所有する鍵、blob、出力バッファのために `alloc` を使用します。ベアメタルアプリケーションはグローバルアロケータを提供する必要があります。ビルドスクリプトは、FFI バインディングの生成時に、`riscv32imac-unknown-none-elf` のような Rust のクロスコンパイルターゲットを clang のターゲット表記に変換します。

`wrapper/rust` ディレクトリには、一般的な作業用の Makefile もあります。C ライブラリのビルド後、`make -C wrapper/rust` でクレートのビルド、lint、ドキュメント生成を行い、`make -C wrapper/rust test` でテストを実行します (ソフトウェア TPM が `localhost:2321` で待ち受けている必要があります)。

## ステップ 3: テストを実行する

統合テストはソケット経由でソフトウェア TPM と通信します。これらは `swtpm-tests` フィーチャーの背後にあるため、通常の `cargo test` では実行中のサーバーは不要です。

ポート 2321 でサーバーを起動します (リポジトリのルートから)。

```sh
./src/fwtpm/fwtpm_server --clear --port 2321 --platform-port 2322 &
```

サーバーに対してテストを実行します。

```sh
cd wrapper/rust/wolftpm
TPM2_SWTPM_HOST=localhost TPM2_SWTPM_PORT=2321 \
    cargo test --features swtpm-tests -- --test-threads=1
```

ソフトウェア TPM は一度に 1 つのクライアントしか処理しないため、`--test-threads=1` を使用してください。

署名テストなど、単一のテストファイルを実行するには次のようにします。

```sh
cargo test --features swtpm-tests --test sign -- --test-threads=1
```

既定のホストとポートは `localhost:2321` であるため、サーバーがそのアドレスにある場合は環境変数を省略できます。

## テストの検証内容

`tests/` 配下の各ファイルは、ソフトウェア TPM に対して 1 つの領域を検証します。

| ファイル | 検証内容 |
| --- | --- |
| `tests/smoke.rs` | 乱数バイト列が取得ごとに異なること、およびプライマリ鍵がロードされること。 |
| `tests/keys.rs` | 子鍵の作成とロード、blob のラウンドトリップ、短い auth の blob のラウンドトリップ、および auth で保護された親鍵。 |
| `tests/sign.rs` | ダイジェストへの署名と検証、および改ざんされた署名の拒否。 |
| `tests/seal.rs` | 秘密情報のシールとアンシール、および誤った auth での失敗。 |
| `tests/seal_pcr.rs` | PCR にバインドされたシールとアンシール、PCR 変更後にアンシールが失敗すること、および無効な PCR 選択の拒否。 |
| `tests/nv.rs` | NV インデックスの定義、書き込みと読み出し、その後の削除。 |
| `tests/pcr.rs` | PCR の読み出し、拡張、および値が変化したことの確認。 |
| `tests/certify.rs` | アテステーション鍵 (ECC と RSA) による別の鍵の certify。 |
| `tests/quote.rs` | ECC および RSA の AIK による PCR の quote、および不正な PCR 選択の拒否。 |
| `tests/credential.rs` | MakeCredential から ActivateCredential へのラウンドトリップ。 |
| `tests/ek.rs` | エンドースメント鍵の作成と、その公開部分のエクスポート。 |
| `tests/persist.rs` | 鍵の永続化、読み戻し、および evict。 |
| `tests/rsa.rs` | RSA-OAEP の暗号化と復号、および明示的な OAEP-SHA1 のラウンドトリップ。 |
| `tests/hmac.rs` | 生の鍵による HMAC、および TPM 常駐の keyed-hash 鍵による HMAC。 |
| `tests/caps.rs` | セルフテストとケイパビリティの問い合わせ。 |
| `tests/ecdh.rs` | ECDH の生成と、同じ共有秘密の復元。 |
| `tests/symmetric.rs` | AES-CFB の暗号化と復号のラウンドトリップ。 |
| `tests/import.rs` | 外部の RSA および ECC 秘密鍵のインポート。 |

## テスト出力の例

```
running 2 tests
test certify_with_ecc_aik ... ok
test certify_with_rsa_aik ... ok
test result: ok. 2 passed; 0 failed; 0 ignored

running 4 tests
test create_and_load_child ... ok
test key_blob_roundtrip_then_load ... ok
test key_blob_roundtrip_preserves_short_auth ... ok
test auth_protected_parent_loads_child ... ok
test result: ok. 4 passed; 0 failed; 0 ignored

running 2 tests
test sign_then_verify ... ok
test verify_rejects_tampered_signature ... ok
test result: ok. 2 passed; 0 failed; 0 ignored

running 2 tests
test rsa_oaep_roundtrip ... ok
test rsa_oaep_sha1_roundtrip ... ok
test result: ok. 2 passed; 0 failed; 0 ignored

running 1 test
test make_and_activate_credential ... ok
test result: ok. 1 passed; 0 failed; 0 ignored
```

## ステップ 4: サンプルを実行する

サンプルは 2 つあります。1 つ目は最小構成です。

```sh
cargo run --example create_primary
```

これはソフトウェア TPM を開き、乱数バイト列を読み出し、RSA と ECC のストレージルートキーを作成します。

2 つ目は API 全体を一度に実行します。

```sh
cargo run --example full_flow
```

期待される出力は次のとおりです。乱数バイト列とハンドル値は実行ごとに異なります。

```
device            connected to software TPM
get_random        a91b37b1838d002453f1632ba2c0adbc
create_primary    ECC SRK handle 0x80000000
create_and_load   signing key handle 0x80000001
sign/verify       64 byte signature, verified
seal/unseal       recovered "my secret"
key blob          257 bytes, reloaded as handle 0x80000002
pcr read/extend   PCR16 000000000000.. -> debb3e7acfff..
nv define/rw      32 bytes at index 0x01500100
certify           157 byte attestation
done              all operations succeeded
```

wolfTPM C ライブラリがデバッグ出力付きでビルドされている場合は、ライブラリからの詳細な TPM2_* トレースも表示されます。通常のビルドでは上記の行のみが出力されます。

## ラッパーの使い方

```rust
use wolftpm::{Device, HashAlg, Hierarchy, KeyAlg, KeyBlob, Template};

fn main() -> Result<(), wolftpm::TpmError> {
    // Connect to a software TPM. Use Device::open() for the platform default.
    let dev = Device::open_swtpm()?;

    // Random bytes from the TPM.
    let mut nonce = [0u8; 32];
    dev.get_random(&mut nonce)?;

    // Storage root key under the owner hierarchy.
    let srk = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;

    // Signing key under the SRK, then sign and verify a digest.
    let signer = dev.create_and_load(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
    let digest = [0x11u8; 32];
    let sig = signer.sign_hash(&digest)?;
    signer.verify_hash(&digest, &sig)?;

    // Seal a secret to the TPM and read it back.
    let sealed = dev.seal(&srk, b"my secret", None)?;
    let _secret = dev.unseal(sealed, &srk, None)?;

    // Persist a key as bytes, then load it again. Scope the reloaded key so it
    // releases its TPM handle before more transient objects are created below
    // (many TPMs allow only three transient objects at once).
    let bytes = {
        let blob = dev.create_key(&srk, &Template::signing(KeyAlg::EccP256)?, None)?;
        blob.to_bytes()?
    };
    {
        let restored = KeyBlob::from_bytes(&dev, &bytes)?;
        let _loaded = restored.load(&srk, None)?;
    }

    // Read and extend a PCR.
    let _value = dev.pcr_read(16, HashAlg::Sha256)?;
    dev.pcr_extend(16, HashAlg::Sha256, &[0xAB; 32])?;

    // Define, write, read, and delete an NV index.
    let mut slot = dev.nv_create(0x0150_0100, 32, None)?;
    dev.nv_write(&mut slot, b"metadata", 0)?;
    let mut buf = [0u8; 32];
    dev.nv_read(&mut slot, &mut buf, 0)?;
    dev.nv_delete(0x0150_0100)?;

    // Attest that a key lives in this TPM, signed by an attestation key.
    let aik = dev.create_and_load(&srk, &Template::attestation(KeyAlg::EccP256)?, None)?;
    let _attestation = dev.certify(&signer, &aik, &nonce)?;

    Ok(())
}
```

鍵とデバイスは、ドロップ時に TPM ハンドルを自動的に解放します。

## クレートが対応する範囲

- デバイスのオープンとクリーンアップ、TPM 乱数、セルフテスト、およびケイパビリティの問い合わせ。
- プライマリ鍵と子鍵。ストレージ、署名、アテステーション、EK、RSA 復号、keyed-hash HMAC、対称 AES、ECDH の各鍵用テンプレート。
- 永続化のための鍵 blob のシリアライズとロード、および外部 RSA / ECC 鍵のインポート。
- 永続鍵ハンドル: 保存、読み戻し、および evict。
- 署名と検証。
- RSA-OAEP の暗号化と復号 (明示的なラベルハッシュを含む。Microsoft エンロールメントとの相互運用には SHA-1)。
- 対称 AES-CFB の暗号化と復号。
- ECDH 鍵共有。
- HMAC (生の鍵を使う場合と、TPM 常駐の keyed-hash 鍵を使う場合の両方)。
- シールとアンシール (通常のものと、PCR ポリシーにバインドされたもの)。
- PCR の読み出しと拡張。
- NV の定義、書き込み、読み出し、削除、および証明書の読み出し (EK 証明書)。
- アテステーション: 鍵の certify と PCR の quote。
- クレデンシャルのアクティベーション: MakeCredential と ActivateCredential。

復元された秘密情報 (unseal、RSA 復号、ECDH、AES 復号、クレデンシャルのアクティベーション) は `Secret` で返され、ドロップ時にそのバッファがゼロ化されます。

## トランスポートのセキュリティ

TPM トランスポートの機密性を確保するには、秘密情報を扱う操作の前に `Device::start_encrypted_session` でパラメータ暗号化セッションを開始します。

```rust
let srk = dev.create_primary(Hierarchy::Owner, KeyAlg::EccP256, None)?;
let _session = dev.start_encrypted_session(&srk)?;  // salted HMAC + AES-CFB
let sealed = dev.seal(&srk, b"secret", None)?;      // command param encrypted
let plain = dev.unseal(sealed, &srk, None)?;        // response param encrypted
```

セッションが有効な間、そのソルト付き HMAC セッションが auth スロット 1 を占有するため、wolfTPM は seal/unseal、RSA と AES の暗号化/復号、HMAC、NV、ECDH、鍵の作成/ロードにおける機微なコマンドパラメータとレスポンスパラメータを暗号化します。同時に許可されるセッションは 1 つのみです。アテステーションコマンド (certify、quote、activate_credential) は同じ auth スロットを必要とするため、セッションがアクティブな間は拒否されます。これらを呼び出す前にセッションをドロップしてください。

!!! warning
    セッションがない場合、パラメータは平文のままトランスポートを流れます。セッションを使用するか、リモートの `TPM2_SWTPM_HOST` や観測可能な物理バスではなく、信頼できるローカルトランスポート (Linux カーネルデバイスやローカルソケット) 上で実行してください。

## ライセンス

wolfTPM と同じく、GPLv3 または wolfSSL の商用ライセンスです。

## 関連項目

- [fwTPM](fwtpm/overview.md)
- [SWTPM](system-interfaces.md)
- [Build Options](build-options.md)
- [C# Wrapper](csharp-wrapper.md)
