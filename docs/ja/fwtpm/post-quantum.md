# fwTPM のポスト量子サポート (TPM 2.0 v1.85)

fwTPM は、wolfCrypt の FIPS 203 (ML-KEM) および FIPS 204 (ML-DSA) モジュールを使用して、TCG TPM 2.0 Library Specification v1.85 のポスト量子に関する追加仕様を実装しています。これにより、TPM シリコンのないプラットフォームにポスト量子の鍵、署名、鍵カプセル化が提供されます。これらの v1.85 コマンドにより、実装済みのコマンド数は 105 から 113 に増加します。ライブラリ全体のポスト量子に関する概要については、[ポスト量子](../post-quantum.md)を参照してください。

configure 時に `--enable-pqc` (エイリアス `--enable-v185`) で有効にします。`--enable-fwtpm` が ML-DSA と ML-KEM の両方を備えた wolfCrypt に対してビルドされる場合にも、自動検出されます。どちらのフラグも、実装を制御する内部マクロ `WOLFTPM_V185` を設定します。自動検出で有効になってしまう場合に無効化するには、`--disable-pqc` を指定します。

## アルゴリズム

| アルゴリズム | パラメータセット | 用途 |
|---|---|---|
| `TPM_ALG_MLKEM` (0x00A0) | ML-KEM-512 / 768 / 1024 | 鍵カプセル化 (復号専用の鍵) |
| `TPM_ALG_MLDSA` (0x00A1) | ML-DSA-44 / 65 / 87 | Pure ML-DSA によるメッセージ署名 |
| `TPM_ALG_HASH_MLDSA` (0x00A2) | HashML-DSA-44 / 65 / 87 | 事前ハッシュ済みの ML-DSA 署名 |

## コマンド

8 つの v1.85 PQC コマンドは `src/fwtpm/fwtpm_command.c` にあります。

| コマンド | CC | 目的 |
|---|---|---|
| `TPM2_Encapsulate` | `0x000001A7` | ML-KEM のカプセル化。sharedSecret と ciphertext を返す |
| `TPM2_Decapsulate` | `0x000001A8` | ciphertext からの ML-KEM のデカプセル化 (USER 認可が必要) |
| `TPM2_SignSequenceStart` | `0x000001AA` | ML-DSA の署名シーケンスを開始 |
| `TPM2_SignSequenceComplete` | `0x000001A4` | メッセージバッファで署名シーケンスを完了 |
| `TPM2_VerifySequenceStart` | `0x000001A9` | ML-DSA の検証シーケンスを開始 |
| `TPM2_VerifySequenceComplete` | `0x000001A3` | 検証シーケンスを完了し、TPMT_TK_VERIFIED を返す |
| `TPM2_SignDigest` | `0x000001A6` | ワンショットのダイジェスト署名 (HashML-DSA または ext-mu ML-DSA) |
| `TPM2_VerifyDigestSignature` | `0x000001A5` | ダイジェスト署名を検証 |

## プライマリ鍵の導出

PQC のプライマリ鍵は、RSA や ECC と同じ決定論的な導出モデルに従います。すなわち、階層シードとテンプレートから KDFa で導出したシードを得て、FIPS 203 または FIPS 204 の鍵展開を行います。

- **ML-DSA:** `KDFa(nameAlg, seed, "MLDSA", hashUnique)` から 32 バイトの Xi が得られます。`wc_MlDsaKey_MakeKeyFromSeed` がこれを公開鍵と展開済みの秘密鍵に変換します。ワイヤフォーマットには、TCG Part 2 Table 210 に従い、32 バイトの Xi のみが格納されます。
- **HashML-DSA:** ラベルは `"HASH_MLDSA"` で、シードのサイズと展開は同じです。
- **ML-KEM:** `KDFa(nameAlg, seed, "MLKEM", hashUnique)` から 64 バイトの値 (d に続けて z) が得られます。`wc_MlKemKey_MakeKeyWithRandom` がこれをカプセル化鍵とデカプセル化鍵に変換します。ワイヤフォーマットには、TCG Part 2 Table 206 に従い、64 バイトのシードのみが格納されます。

!!! note
    これらのラベル文字列は解釈に基づくものです。これらを規範的に規定するはずの TCG Part 4 v185 は未公開です。後のリリース候補または Part 4 v185 が異なるラベルを規定した場合、変更される可能性があります。

## 署名および検証シーケンス

Pure ML-DSA のシーケンスは、署名と検証の両方でストリーミングが可能なため、`TPM2_SequenceUpdate` が受け付けられます。`TPM_RC_ONE_SHOT_SIGNATURE` が適用されるのは EdDSA のようなマルチパスのスキームであり、Pure ML-DSA には適用されません。呼び出し側は、メッセージ全体を `TPM2_SignSequenceComplete` の `buffer` パラメータ経由で渡すこともできます。`TPM2_VerifySequenceComplete` には buffer パラメータがないため、検証シーケンスは `TPM2_SequenceUpdate` を通じてメッセージを蓄積します。

HashML-DSA のシーケンス (署名と検証の両方) は、wolfCrypt の `wc_HashAlg` コンテキストを使用して、メッセージを鍵のハッシュアルゴリズムへストリーミングします。`TPM2_SignSequenceComplete` はハッシュを完了し、`wc_MlDsaKey_SignCtxHash` を呼び出します。

署名のワイヤフォーマットは、仕様 Part 2 Table 217 に従って異なります。

- **Pure ML-DSA:** `TPM2B_SIGNATURE_MLDSA`。`sigAlg + size + bytes` の配置
- **HashML-DSA:** `TPMS_SIGNATURE_HASH_MLDSA`。`sigAlg + hashAlg + size + bytes` の配置

## バッファ定数

`WOLFTPM_V185` のもとでは、ML-DSA-87 の署名 (4627 バイト) と公開鍵 (2592 バイト) に収まるようにバッファが拡大されます。

| シンボル | v1.38 | v1.85 |
|---|---|---|
| `FWTPM_MAX_COMMAND_SIZE` | 4096 | 8192 |
| `FWTPM_MAX_PUB_BUF` | 512 | 2720 |
| `FWTPM_MAX_DER_SIG_BUF` | 256 | 4736 |
| `FWTPM_MAX_KEM_CT_BUF` | n/a | 1600 |
| `FWTPM_TIS_FIFO_SIZE` | 4096 | 8192 |
| `FWTPM_NV_PUBAREA_EST` | 600 | 2720 |

これらは最悪ケースの値です。デフォルト値は、wolfCrypt のビルド時に有効だったパラメータセットに合わせて、コンパイル時に縮小されます。パラメータセットごとの表については、[ビルド](building.md)の "v1.85 Embedded RAM Impact" を参照してください。

## 制限事項と対象範囲

v1.85 コマンドは、ポスト量子の鍵に対してのみ実装されています。仕様がこれらのコマンドを汎用的に定義している場合でも、PQC 以外の鍵タイプは `TPM_RC_KEY` または `TPM_RC_SCHEME` で拒否されます。

- `TPM2_Encapsulate` と `TPM2_Decapsulate`: ML-KEM のみ。ECC DHKEM (非 NULL の KDF を伴う Table 100 の `ecdh` アーム) は実装されていません。
- `TPM2_SignSequenceStart`、`TPM2_VerifySequenceStart`、`TPM2_SignSequenceComplete`、`TPM2_VerifySequenceComplete`: ML-DSA と HashML-DSA のみ。仕様がこれらのコマンドを通じて許可している従来のスキーム (RSASSA、RSAPSS、ECDSA、SM2、ECSCHNORR、HMAC) はサポートされていません。
- `TPM2_SignDigest` と `TPM2_VerifyDigestSignature`: ML-DSA と HashML-DSA のみ。これらの新しいコマンドによる従来のダイジェスト署名 (RSASSA、RSAPSS、ECDSA) はサポートされていません。これらのスキームには、既存の `TPM2_Sign` と `TPM2_VerifySignature` コマンドを使用してください。

## 先送りおよび対象外

3 つの v1.85 機能は、それぞれ文書化された理由により先送りされています。

1. **ML-KEM をソルトとするセッション。** Part 3 Sec.11.1 (`TPM2_StartAuthSession`) には、RSA-OAEP と ECDH のパスに並ぶ ML-KEM の項目の記述がありませんが、Part 2 Sec.11.4.2 Table 222 は `TPMU_ENCRYPTED_SECRET` の `mlkem` アームを定義しています。これを規範的に規定するはずの Part 4 v185 は、まだ公開されていません。現在の動作: ML-KEM の tpmKey に対して `TPM2_StartAuthSession` は `TPM_RC_KEY` を返します。Part 4 v185 が公開された時点で見直します。
2. **External-mu ML-DSA 署名。** wolfCrypt には mu を直接指定する署名 API がありません。Part 2 Sec.12.2.3.7 は "512-byte external Mu" としていますが、FIPS 204 Algorithm 7 Line 6 は 64 バイト (SHAKE256 の出力) を生成します。wolfCrypt への API 追加と TCG の正誤表による確認を待っています。現在の動作: ext-mu のパスには `TPM_RC_SCHEME` を、`allowExternalMu` のない Pure ML-DSA 鍵には `TPM_RC_EXT_MU` を返します。
3. **Encapsulate と Decapsulate の ECC KEM アーム。** Part 2 Sec.10.3.13 Table 100 には `mlkem` と `ecdh` の両方のアームがありますが、表の注記では、実装がサポートするアルゴリズムに基づいてユニオンを変更することを許容しています。fwTPM がサポートするのは `mlkem` アームのみです。

## テストカバレッジ

`tests/fwtpm_unit_tests.c` には、全パスを検証する 10 個の PQC テストが含まれています。

- ML-KEM-768 と ML-DSA-65 の CreatePrimary
- Encapsulate と Decapsulate の完全なラウンドトリップ (共有秘密のバイト一致)
- HashML-DSA の SignDigest と VerifyDigestSignature のラウンドトリップ
- Pure ML-DSA の署名シーケンスと検証シーケンスのラウンドトリップ
- ML-DSA-44 の検証、ML-DSA-44 の鍵生成の決定性、乱数を固定した ML-KEM-512 のカプセル化、ML-KEM-512 の鍵生成の決定性に対する、2 つのソース (NIST ACVP と wolfSSL 内部ベクタ) による既知解テスト
- fwTPM ハンドラー経由での NIST ACVP の ML-DSA-44 公開鍵の LoadExternal

## 関連項目

- [概要](overview.md)
- [ビルド](building.md)
- [使用方法](usage.md)
- [SPDM レスポンダ](spdm.md)
- [ポスト量子 (ライブラリ全体)](../post-quantum.md)
