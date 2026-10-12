# リリースノート

このページでは、wolfTPM の最近のリリースを追跡します。リポジトリの ChangeLog から、Unreleased セクションと直近 2 つのリリースを転載しています。最初のリリースまでの完全な履歴は、リポジトリ最上位の [ChangeLog.md](https://github.com/wolfSSL/wolfTPM/blob/master/ChangeLog.md) にあります。

## Unreleased

* TPM が割り当てる PCR バンクを変更するための `wolfTPM2_AllocatePCRBanks` を追加しました。
  - バンクの確認と再プロビジョニングを行う `examples/pcr/allocate` を追加しました。
  - fwTPM が、TPM 2.0 Part 3 22.5 に従って次回の `Startup(CLEAR)` で適用すべき割り当てを即座に適用していた問題、PCR バンクが 1 つも残らない選択を受け入れていた問題、`pcrSelect` ビットマップを無視していた問題、既存の NV ファイルに対する再起動後に割り当て済みバンクが報告されなかった問題を修正しました。

## wolfTPM Release 4.2.0 (Sep 14, 2026)

**Summary**

fwTPM (ファームウェア TPM) における TCG TPM 2.0 v1.85 仕様への準拠、ポスト量子暗号サポートの拡充、新しいプラットフォームバックエンドを中心とした、機能追加およびメンテナンスリリースです。主な内容は次のとおりです。fwTPM の v1.85 準拠に関する幅広い修正 (コマンド属性、PolicyAuthorize、コンテキスト Blob の認証、NV 認可、チケット HMAC の順序) と SPDM レスポンダの修正。ポスト量子 TLS 1.3 向けの ML-DSA 認証と SealSQ QVault ポスト量子 TPM のサポート。wolfHAL の I2C/SPI バックエンドと NVIDIA Jetson Orin OP-TEE fwTPM のサポート。ST33 ファームウェアアップデートの修正。トランスポートおよび NV/ハッシュの性能改善。広範なセキュリティ強化 (Coverity、静的解析、ネガティブテスト)。

**Detail**

* ファームウェア TPM (fwTPM) の TCG v1.85 仕様準拠
  - コマンドコードのマスキングとベンダービットのリターンコードの修正 (PR #556)
  - 認証エントリ処理の修正 (PR #566)
  - PolicyAuthorize の準拠修正、および keySign の name チケットと approvedPolicy に対する応答コードの修正 (PRs #567, #572)
  - ContextSave/ContextLoad でオブジェクトのコンテキスト Blob を認証 (PR #568)
  - サポートされない LoadExternal の秘密鍵タイプを拒否、作成チケット HMAC の順序を修正、LoadExternal と CreateLoaded で ML-DSA / ML-KEM テンプレートを検証 (PRs #573, #578)
  - NV 領域の認可を検証し、v1.85 リビジョンを報告 (PR #575)
  - 階層およびポリシー認可の不備と、SPDM レスポンダのバージョンネゴシエーションを修正 (PR #577)
  - コマンド属性の報告と、検証済みチケットの HMAC アルゴリズムを修正 (PR #579)
  - TCG v1.85 に関する fwTPM と SPDM の追加の準拠修正 (PR #584)
* ポスト量子暗号と TLS
  - ポスト量子 TLS 1.3 向けの TPM ベースの ML-DSA 認証。サンプルとテストを含む (PR #559)
  - SealSQ QVault ポスト量子 TPM のサポート (PR #570)
  - fwTPM における ML-KEM クレデンシャルのアクティベーションと ML-DSA クォート (PR #592)
* 新しいプラットフォームと HAL のサポート
  - `--enable-wolfhal` とアプリケーション提供の `board.h` で有効化される wolfHAL の I2C および SPI バックエンド (PR #562)
  - Linux TPM カーネルドライバ経由で `/dev/tpmrm0` として利用する、NVIDIA Jetson Orin (Tegra234) の OP-TEE ファームウェア TPM (PR #576)
  - fwTPM におけるコマンドグループ単位のより細かいゲーティングマクロ (PR #574)
  - ファームウェアアップグレード向けの、呼び出し元が指定するポリシー認可 (PR #560)
* ST33 ファームウェアアップデート
  - Generation 1 のマニフェストサイズを修正し、サイズ超過のコマンドを拒否 (PR #583)
  - TPM のコマンドセットから ST33 のフィールドアップグレードコマンドを選択 (PR #586)
* 性能
  - トランスポート接続を再利用し、NV 書き込みとハッシュキャッシュのオーバーヘッドを削減 (PR #563)
* セキュリティ強化 (Coverity、静的解析、入力検証)
  - ネガティブテストとともに、crypto コールバック、ASN.1 解析、パラメータ暗号化、マーシャリングを強化 (PR #551)
  - TPM2 応答の復号パラメータサイズに上限を設け、プライマリキーの認証値をゼロ化し、マーシャリング/インポートのテストカバレッジを拡充 (PR #555)
  - fwTPM のプロパティパスにおける、汚染された PCR 選択のコピーを保護 (PR #558)
  - fwTPM の応答バッファオーバーフローと、SPDM クリアフレームによるコマンドバイパスを修正 (PR #561)
  - wolfTPM2 の PCR/ハッシュラッパーの検証を強化 (PR #554)
  - TPM の入力検証とメモリ処理を強化 (PR #565)
  - P521 プライマリ導出における wolfCrypt の参照カウント競合と、ポリシーセッション認可のバイパスを修正 (PR #571)
  - PCR ポリシーの境界チェックを強化 (PR #581)
  - wolfTPM の検証とデータ処理を強化 (PR #582)
  - fwTPM のプロトコル処理と SPDM 認証を強化 (PR #588)
  - fwTPM の状態変更をトランザクション化し、PolicyPCR と秘密 Blob のラッピングを強化 (PR #593)
  - TPM の境界および構成パスにわたる Coverity の追加修正。fwTPM の子 Blob コピーの上限設定、公開名バッファ確保のガード、アンシールした出力ファイルの権限制限を含む (PRs #591, #595, #603, #605)
  - fwTPM の鍵導出とコマンド検証を強化 (PR #596)
  - TPM2 コアの鍵インポート解析と応答処理を修正し、コアのゼロ化と堅牢性を改善 (PRs #597, #600)
  - サンプル、SPI 転送、SPDM バージョン解析におけるエラー処理と秘密情報のゼロ化を強化 (PRs #598, #599, #604)
  - 切り詰められた fwTPM の Rewrap 入力を拒否、空ポリシーのオブジェクトに対するポリシーセッションにバインドされた認可を要求、keyed-hash の秘密全体を公開名にバインド、公開領域の解析でオーバーフロー時に失敗、TIS ロケーリティの戻り値を正規化、共有コマンドバッファに残ったリクエストバイトをクリア (PR #608)
* ビルド修正
  - OPENSSL_COEXIST の wolfSSL で AES_BLOCK_SIZE が未宣言になる問題を修正 (PR #552)
  - TIS ロックありで wolfCrypt なしというエッジケースのビルドを修正 (PR #564)
  - `--disable-wolfcrypt` と `--enable-pqc` を併用したビルドを修正 (PR #606)
  - 期限切れの wolfSSL サンプル CA 証明書を更新し、更新スクリプトを追加 (PR #601)
* ドキュメントとライセンス
  - コントリビューションガイダンス (CONTRIBUTING.md) を追加 (PR #569)
  - ベースとなる GPLv3 ライセンスに対する GPLv2 例外: Cisco Systems, Inc. の U-Boot と組み合わせた wolfTPM は GPLv2 でライセンスできます (PR #557)

## wolfTPM Release 4.1.0 (Jul 10, 2026)

**Summary**

TPM ロケーリティ制御とポスト量子暗号サポートの拡充を中心とした機能追加リリースです。主な内容は次のとおりです。実行時のロケーリティ選択 (`wolfTPM2_SetLocality`)、修正された fwTPM の PCR ごとのロケーリティ強制テーブル、オプションの GPIO nRST リセット HAL。きめ細かなビルドマクロを備えた、ファームウェア TPM への TPM 2.0 v1.85 ポスト量子暗号 (ML-DSA / ML-KEM) サポートの導入。fwTPM のディクショナリアタック対策の強化、`TPM_RC_RETRY` の透過的な処理、fwTPM 向けの SPDM セキュアトランスポート。FIPS 140-3 機能の報告。フリースタンディング (libc なし) ビルドのサポート。EU サイバーレジリエンス法 (CRA) への準拠に向けた SBOM (CycloneDX / SPDX) の生成。広範なセキュリティ強化 (Coverity、CodeQL)。

**Detail**

* 実行時の TPM ロケーリティ制御 (PR #546)
  - 新しい `wolfTPM2_SetLocality(dev, locality)` により、ロケーリティ 0-4 を実行時に選択できます。`examples/pcr/reset` は `-loc=n` フラグを受け付けます。組み込みの TIS/SPI ドライバ (プリエンプトしないチップ向けの解放とリトライを含む) と、ソケットおよび TIS/SHM 経由の fwTPM で動作します。ロケーリティを選択できない環境 (I2C、Linux カーネルドライバ、Windows TBS) では `NOT_COMPILED_IN` を返します
  - fwTPM の PCR ごとのロケーリティ強制を、単一の信頼できる情報源となるテーブル (TCG PC Client プロファイル) に置き換えました。リセットマップを修正し、欠けていた PCR extend のチェックを追加し、適切な `RESET_L*`/`EXTEND_L*`/`DRTM_RESET` ビットマップを報告します。動作の変更: DRTM の PCR 17-22 はロケーリティ 0 から extend できなくなりました (`TPM_RC_LOCALITY` を返します)
  - `TPM_CAP_ALGS`/`TPM_CAP_COMMANDS` のページングがプロパティカーソルを尊重するよう修正し、`moreData` に従うクライアントが先へ進めるようにしました
  - オプションのハードウェアリセット HAL: `--enable-hal-reset[=LINE]` は `TPM2_IoCb_Reset()` を追加し、Linux GPIO キャラクタデバイス経由で nRST ラインにパルスを送ります (デフォルトは ST33 が GPIO24、Nuvoton が GPIO4)
* fwTPM における TPM 2.0 v1.85 ポスト量子暗号 (PQC) サポート: ML-DSA の署名/検証、ML-KEM のカプセル化/デカプセル化、および TCG Phase B に沿ったシード処理。PQC の CI とファズのカバレッジを含む (PR #445)
  - フットプリントを削減するための、きめ細かなビルドマクロ: `WOLFTPM_PQC` (新しい軽量な `--enable-pqc`)、アルゴリズムごとの `WOLFTPM_MLDSA`/`WOLFTPM_MLKEM`、操作ごとのゲート、および `--enable-mldsa[=...]` / `--enable-mlkem[=...]` / `--disable-hash-mldsa` (PRs #527, #533)
  - wolfSSL v5.8.0 以上という PQC の下限バージョンと、上流の変更を検知する CI。サンプルにおける ML-DSA の `TPM2_CreateLoaded` プライマリと PQC パラメータ暗号化。新しい `_ex` のセッション/OAEP/PQC ハッシュ用ラッパー (PRs #501, #509, #531, #539, #520)
* TCG 仕様に沿った fwTPM のディクショナリアタック (DA) 対策の強化 (PR #541): オブジェクトでの `noDA` の尊重、非正常シャットダウン時のペナルティとともに `failedTries` を永続化、`recoveryTime`/`lockoutRecovery` による自己回復、`TPM2_GetCapability` による DA プロパティの報告。`wolfTPM2_DictionaryAttackLockReset`/`wolfTPM2_DictionaryAttackParameters`、`examples/management/da_check` サンプル、`tests/fwtpm_da_retry.sh` ハーネスを追加
* 一時的にビジー状態を報告する TPM 向けの、オプションの `TPM_RC_RETRY` 透過処理。`TPM2_SetCommandRetries` または `-DWOLFTPM_MAX_RETRIES=N` で有効化し、`WOLFTPM_NO_RETRY` でコンパイル時に除外できます (PR #537)
* SPDM セキュアトランスポートの fwTPM への拡張 (PR #510)、および FIPS 140-3 機能の報告 (PR #502)
* fwTPM のセッション、ポリシー、NV の修正: コマンドポート再接続をまたいだ一時的な状態の保持、パスワード認証応答での `continueSession` の設定、PolicyAuthorize のゼロチケット処理、ライトワンスフラッシュ向けポートの追記専用 NV ジャーナル (PRs #518, #530, #517, #540)
* 新しいサンプルとオプション: 暗号プリミティブのサンプル (getrandom、hash、AES、ECDH)、`WOLFTPM2_ECC_DEFAULT_CURVE` オプション (ZD 21780)、native_test における ECC P-384 のカバレッジ (PRs #532, #519, #492)
* Nations NS350 のサンプルスイートの修正: RSA-4096 のバッファサイズと、保存済みキータイプからの SRK アルゴリズム選択 (PR #494)
* フリースタンディングビルドのサポート: `WOLFTPM_NO_STD_HEADERS` により、ベアメタル向けの統合で `tpm2_types.h` から標準 C ヘッダーを除外します。`freestanding-build.yml` の CI ジョブも追加 (PR #549)
* EU サイバーレジリエンス法 (CRA) への準拠に向けたソフトウェア部品表 (SBOM) の生成: 新しい `make sbom` / `install-sbom` の autotools ターゲットと CMake の `sbom` ターゲットにより、ビルドされたライブラリ向けの CycloneDX および SPDX ドキュメントを出力し、wolfSSL を依存関係として記録します (PR #536)
* セキュリティ強化: 自動セキュリティレビュー (TPM2 パケットパーサーとマーシャリングの境界/範囲外アクセスの修正、秘密情報のゼロ化、ポリシー/チケットのバイパス修正)、fwTPM の PCR/シード/ハッシュ/シールの各パスにわたる Coverity の修正、CodeQL/Semgrep/Copilot のレビューゲート、`TPM2_ASN_RsaUnpadPkcsv15` におけるヒープ範囲外読み取りの修正 (PRs #496, #503, #511, #512, #518, #523, #535, #545, #547, #548, #543, #542, #544, #538, #513, #514, #524, #528, #507, #516)
* CI とビルドの改善: CMake のテストケースの拡充、GHCR コンテナイメージ、夜間ファジング、wolfSSL の最新安定版の自動解決、事前スモークテスト (PRs #495, #534, #522, #525, #508, #526, #521)
* バグ修正
  - wolfSSL PR 10604 に対応するため、wolfCrypt の crypto コールバックが `ALREADY_E` を伝播するよう修正 (PR #546)
  - crypto コールバックとともに wolfCrypt の DRBG が使用されるようにし、HW RNG を備えた TPM では `TPM2_StirRandom` を TCG 準拠の何もしない処理にしました (PRs #498, #493)
  - StartAuth のセッションノンスに TPM の RNG を使用する際の注意事項を追加 (ZD 21476, PR #478)


## 全履歴

これより古いリリースはここでは繰り返しません。すべてのリリースについては、リポジトリのルートにある `ChangeLog.md` を参照してください。

## 関連項目

- [テストと CI](testing.md)
- [SBOM とコンプライアンス](sbom-and-compliance.md)
- [API リファレンス](api-reference.md)
