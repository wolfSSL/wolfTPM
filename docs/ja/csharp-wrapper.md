# C# ラッパー

`wrapper/CSharp` ディレクトリには、wolfTPM の TPM 2.0 API 向け C# ラッパーが含まれています。P/Invoke を通じてネイティブの `wolftpm` ライブラリにバインドするため、先にネイティブライブラリをビルドしておく必要があります。テストは NUnit を使用し、.NET (Windows) または Mono (Linux) 上で実行されます。

wolfTPM の `README.md` の説明に従って wolfSSL をビルドし、その後、お使いのプラットフォームに応じて以下の説明に従い wolfTPM をビルドしてください。Linux では、テストに swtpm TCP シミュレータを使用します。

## Windows

ラッパーをビルドするための Visual Studio ソリューションが用意されています。テストを実行するには、`.runsettings` ファイルを更新して `wolftpm.dll` の場所を追加します。このファイルには vcpkg ビルド用のプレースホルダーがありますが、Visual Studio で wolfTPM をビルドする際に CMake を使用することもできます。

Windows で wolfTPM をビルドするための CMake 設定の例:

```
"WOLFTPM_INTERFACE": "WINAPI",
"WOLFTPM_EXAMPLES": "no",
"WOLFTPM_DEBUG": "yes",
"WITH_WOLFSSL": "C:/Users/[username]/wolfssl/out/install/windows-default"
```

## Linux

このラッパーは、シミュレータ用の swtpm TCP プロトコルで動作確認されています。シミュレータのビルドと実行については [SWTPM](system-interfaces.md) を参照してください。

wolfTPM をビルドします。

```sh
./autogen.sh
./configure --enable-swtpm
make all
make check
```

Mono と NUnit の前提パッケージをインストールします。

```sh
apt install mono-tools-devel nunit nunit-console
```

続いて、ラッパーとそのテストをビルドして実行します。

```sh
cd wrapper/CSharp
mcs wolfTPM.cs wolfTPM-tests.cs -r:/usr/lib/cli/nunit.framework-2.6.3/nunit.framework.dll -t:library

# run the selftest case
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll -run=tpm_csharp_test.WolfTPMTest.TrySelfTest

# run all tests
LD_LIBRARY_PATH=../../src/.libs/ nunit-console wolfTPM.dll
```

セルフテストを実行すると、次のような出力が表示されます。

```
Selected test(s): tpm_csharp_test.WolfTPMTest.TrySelfTest

wolfSSL Entering wolfCrypt_Init
.
Tests run: 1, Errors: 0, Failures: 0, Inconclusive: 0, Time: 0.1530346 seconds

  Not run: 0, Invalid: 0, Ignored: 0, Skipped: 0

wolfSSL Entering wolfCrypt_Cleanup
```

!!! note
    ソースの README にはラッパーの API 範囲に関する説明がありません。このページには、公開されているクラスと使用例を扱う新しい本文を後日追加する必要があります。

## 関連項目

- [SWTPM](system-interfaces.md)
- [Build Options](build-options.md)
- [Rust Wrapper](rust-wrapper.md)
