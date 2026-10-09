# テスト

このページでは、wolfTPM のテストをローカルで実行する方法と、リポジトリ上で動作する継続的インテグレーション (CI) のワークフローを説明します。

## ローカルでのテスト実行

メインのテストスイートをビルドして実行します。

```sh
./configure
make check
```

`make check` は、ユニットテスト、fwTPM テスト、ポスト量子暗号 (PQC) テストを実行します。ユニットテストのソースは次のとおりです。

| ファイル | 目的 |
|---|---|
| `tests/unit_tests.c` | wolfTPM ライブラリのユニットテスト |
| `tests/fwtpm_unit_tests.c` | fwTPM コマンドプロセッサのユニットテスト |
| `tests/fwtpm_hal_unit_tests.c` | fwTPM HAL のユニットテスト |

シェルベースのテストは次のとおりです。

| ファイル | 目的 |
|---|---|
| `tests/fwtpm_check.sh` | `make check` が fwTPM テストに使用するエントリポイント |
| `tests/fwtpm_da_retry.sh` | ディクショナリアタックとリトライ処理 |
| `tests/pqc_mssim_e2e.sh` | ポスト量子暗号のエンドツーエンドテスト |

TPM またはシミュレータに対してサンプルプログラムを実行するには、次を使用します。

```sh
./examples/run_examples.sh
```

このスクリプトは次の環境変数を読み取ります。

| 変数 | 目的 |
|---|---|
| `WOLFSSL_PATH` | サンプルが使用する wolfSSL ビルドへのパス |
| `WOLFCRYPT_ENABLE` | wolfCrypt サポートが組み込まれている場合に設定 |
| `NO_FILESYSTEM` | ファイルシステムを必要とするサンプルをスキップ |
| `ENABLE_DESTRUCTIVE_TESTS` | TPM のクリアなど、TPM の状態を変更するテストも実行 |

!!! warning
    破壊的テストは TPM を変更します。必要な鍵やデータを保持している TPM では有効にしないでください。

## CI ワークフロー

ワークフローは `.github/workflows/` にあります。表には各ファイルのワークフロー名を示しています。

| ファイル | 名前 |
|---|---|
| `_resolve-wolfssl.yml` | Resolve wolfSSL versions |
| `cmake-build.yml` | WolfTPM CMake Build Tests |
| `codeql.yml` | CodeQL |
| `codespell.yml` | Codespell |
| `coverity-scan-fixes.yml` | Coverity Scan master branch |
| `docs-site.yml` | Build manual with documentation tooling |
| `freestanding-build.yml` | Freestanding Build (WOLFTPM_NO_STD_HEADERS) |
| `fuzz.yml` | Fuzz Testing |
| `fwtpm-test.yml` | fwTPM Tests |
| `make-test-swtpm.yml` | WolfTPM Build Tests |
| `multi-compiler.yml` | Multiple Compilers |
| `nightly.yml` | Nightly CI |
| `pqc-build-matrix.yml` | PQC Build Matrix (v1.85 trimming) |
| `pqc-examples.yml` | PQC Examples (v1.85) |
| `publish-ci-image.yml` | Publish wolfTPM CI image |
| `publish-docs-image.yml` | Publish documentation image |
| `release-checks.yml` | Release Checks |
| `rust-test.yml` | WolfTPM Rust Wrapper Tests |
| `sanitizer.yml` | Sanitizer Tests |
| `sbom.yml` | SBOM Test |
| `seal-test.yml` | Seal Test Suite |
| `semgrep.yml` | Semgrep |
| `smoke-test.yml` | Smoke Test |
| `spdm-test.yml` | SPDM Test |
| `win-swtpm-test.yml` | Windows swtpm Transport Test |
| `win-test.yml` | Windows Build Test |
| `wolfhal-build.yml` | wolfHAL Build Tests |
| `wolfssl-versions-pqc.yml` | wolfSSL Version Matrix |
| `zephyr.yml` | Zephyr wolfTPM Tests |

## 関連項目

- [ベンチマーク](benchmarks.md)
- [SBOM とコンプライアンス](sbom-and-compliance.md)
- [リリースノート](release-notes.md)
