# SBOM とコンプライアンス

wolfTPM は、EU サイバーレジリエンス法 (CRA) への準拠を支援するため、ソフトウェア部品表 (SBOM) を生成できます。このページでは、その生成方法とジェネレータの構成を説明します。

## SBOM と EU CRA コンプライアンス

wolfTPM は CycloneDX 1.6 および SPDX 2.3 形式で SBOM を生成します。ジェネレータは `tools/sbom/` にベンダリングされた wolfGlass のスナップショットで、`tools/sbom/.wolfglass-rev` で固定されています。SBOM には、設定されたビルドオプション (`wolftpm/options.h` から取得)、ビルドされた `libwolftpm` ライブラリ成果物 (共有または静的、ELF、Mach-O、PE) のハッシュ、および依存関係としての wolfSSL が記録されるため、脆弱性スキャナーは wolfSSL のアドバイザリを wolfTPM のデプロイメントに関連付けることができます。

出力は再現可能です。`SOURCE_DATE_EPOCH` を設定する (または最後のコミット時刻が使用される git チェックアウトからビルドする) と、繰り返し実行しても出力はバイト単位で同一になります。

autotools の場合:

```sh
make sbom
```

これには `python3` と `pyspdxtools` (`pip install spdx-tools`) が必要です。ジェネレータはツリーに同梱されているため、`make sbom` に別途 wolfSSL のチェックアウトは必要ありません。このビルドがリンクした wolfSSL を pkg-config が認識できない場合は、`WOLFSSL_DIR=/path/to/wolfssl` を渡すと、依存関係のバージョンが `wolfssl/version.h` から読み取られます。`SBOM_WOLFSSL_VERSION` を指定すると、この検出結果を上書きできます。

CMake ビルドでも同じターゲットを利用できます。`WOLFSSL_DIR` は任意で、意味は同じです。

```sh
cmake -B build .
cmake --build build --target sbom
```

出力ファイルは次のとおりです。

- `wolftpm-<version>.cdx.json`
- `wolftpm-<version>.spdx.json`
- `wolftpm-<version>.spdx`

任意の上書き設定:

| 変数 | 目的 |
|---|---|
| `SBOM_LICENSE_OVERRIDE` | `COPYING` から解析されたライセンスの代わりに使用する SPDX 式 (例: 商用ライセンス利用者向けの `LicenseRef-wolfSSL-Commercial`)。デフォルトは、ファイルごとのヘッダーに記載されたライセンスである `GPL-3.0-or-later` です。 |
| `SBOM_LICENSE_TEXT` | `SBOM_LICENSE_OVERRIDE` で使用する `LicenseRef-*` のライセンス本文へのパス (SPDX 2.3 で必須)。 |
| `SBOM_WOLFSSL_VERSION` | wolfSSL 依存関係として記録されるバージョン。未設定の場合は `WOLFSSL_DIR/wolfssl/version.h` (または wolfSSL の `pkg-config` エントリ) から自動検出されます。 |

生成されたファイルをインストールするには:

```sh
make install-sbom    # installs to $(datadir)/doc/wolftpm/
make uninstall-sbom
```

CRA に関するさらなるガイダンスは [wolfssl/doc/CRA.md](https://github.com/wolfSSL/wolfssl/blob/master/doc/CRA.md) を参照してください。

## ジェネレータの内部構成

wolfGlass のうち、ベンダリング可能なのは `share/` セットのみです。`tools/wolfglass-sync` スクリプトは、これらのファイルを、固定用ファイル (`VERSION` と `.wolfglass-rev`) とともに、製品内の `tools/sbom/` にコピーします。コピーするのはファイルであり、`share/` フォルダ名ではありません。

### 内容

| ファイル | 役割 |
|---|---|
| `sbom-driver.py` | 製品に依存しない SBOM エンジン (Python)。 |
| `sbom-driver` | `sbom-driver.py` を実行する薄いシェルラッパー。 |
| `validate_sbom.py` | CI 向けの構造バリデータ (`--name-prefix`)。 |
| `frontends/compdb_sbom.py` | 任意の `compile_commands.json` に対するエクストラクタ。 |
| `frontends/iar_sbom.py` | IAR Embedded Workbench の `.ewp` に対するエクストラクタ。 |
| `frontends/zephyr_sbom.py` | Zephyr モジュールの `CMakeLists.txt` に対するエクストラクタ。 |
| `build/sbom.mk` | 共有のプレーン Make フラグメントと `wolfglass_sbom_rule` マクロ。 |
| `build/sbom.cmake` | 共有の CMake ヘルパー: `wolfglass_add_sbom()`。 |
| `gen-sbom` | ベンダリングされた SBOM ジェネレータ。 |
| `sbom.am` | 共有の autotools フラグメント。 |

### ドライバの契約

すべてのフロントエンドは、コンポジション入力とコンフィグ入力を生成し、ドライバに渡します。

コンポジション (少なくとも 1 つ):

- `--srcs-file PATH`: 成果物にコンパイルされるソースファイル (tier E)。
- `--lib PATH`: ハッシュ対象のビルド済みライブラリ (tier R/L/S)。
- `--no-artifact-hash`: 成果物をビルド済みのまま記録し、再ハッシュしません。FIPS キャニスターやカーネルモジュールでは `--lib` と併用します。認証済み成果物の代わりにソースリストを使用してはいけません。

コンフィグ (いずれか 1 つを選択):

- `--cflags="..."`: 生の CFLAGS。ドライバはホストコンパイラを通して `-D` トークンを展開します。先頭がダッシュの値がフラグとして解釈されないよう、`=` 形式を使用してください。
- `--options-h PATH`: 事前展開済みのフラットな `#define` ヘッダー。そのまま使用されます。
- `--user-settings PATH`: ジェネレータが取り込む `user_settings.h`。
- `--source-only`: ビルド設定マクロなし (例: Kconfig 駆動のビルド)。

依存関係 (リンカーとバインディング向け): `--dep-wolfssl`、`--dep-openssl`、`--dep-version` は、ジェネレータが対応している場合にのみ受け渡されます。

ドライバはホストコンパイラでマクロを取得するため、SBOM はツールチェーンをまたいで再現可能です。`--no-scrub` を指定しない限り、取得したマクロからホストの絶対パスを除去します。

共有ドライバは製品に依存せず、デフォルトではベンダリングされた `share/gen-sbom` を呼び出します。そのコピーを上書きしたい場合にのみ `--gen-sbom` を指定してください。

### マニフェストの契約

製品はロジックをコピーしません。自身を記述します。

- **Make:** `SBOM_NAME`、`SBOM_SRCS`、`SBOM_CFLAGS`、およびバージョン (`SBOM_VERSION`、または `SBOM_VERSION_FILE` と `SBOM_VERSION_MACRO`) を設定し、`include tools/sbom/build/sbom.mk` します。2 つ目のターゲットには `$(eval $(call wolfglass_sbom_rule,<target>,<prefix>))` をインスタンス化します。製品の構成が `user_settings.h` にある場合は、`SBOM_SETTINGS_H` も設定します (そのヘッダーが CFLAGS にまだ含まれていないパスを必要とする場合は `SBOM_INCLUDE_DIRS` も設定)。`SBOM_CFLAGS` だけでは、文字どおりの `-D` の集合のみが記録され、そこから派生するものは記録されません。ゲートされたヘッダーでは、SBOM が誰もビルドしていない構成を記述してしまうことになります。
- **CMake:** `include(tools/sbom/build/sbom.cmake)` し、`NAME`、`VERSION_FILE`、`VERSION_MACRO`、`TARGETS`、`DEFS`、`LICENSE` を指定して `wolfglass_add_sbom()` を呼び出します。`SBOM_GEN` が正式なジェネレータ上書き用の変数です。`GEN_SBOM` は互換性のため、従来のエイリアスとして残されています。
- **Autotools:** `SBOM_*` 変数を設定し、`include tools/sbom/sbom.am` します。

製品に残すのは、真に製品固有の知識のみです。具体的には、ルーティング用スクリプト、モジュールエクストラクタ、HAL ソースセレクタです。

## 関連項目

- [テストと CI](testing.md)
- [リリースノート](release-notes.md)
- [API リファレンス](api-reference.md)
