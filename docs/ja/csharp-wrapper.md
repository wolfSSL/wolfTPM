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

## API の概要

すべてのラッパー型は `wrapper/CSharp/wolfTPM.cs` の `wolfTPM` 名前空間にあります。各クラスはネイティブの wolfTPM オブジェクトを包む薄いクラスで、`wolftpm` ライブラリへの P/Invoke 呼び出しによって確保と解放が行われます。

| 型 | 用途 |
| --- | --- |
| `Device` | TPM への接続。ネイティブの `WOLFTPM2_DEV` を保持し、すべての TPM 操作を提供します。 |
| `Key` | ロード済みの TPM 鍵 (ストレージルート鍵 (SRK) やプライマリ鍵など)。 |
| `KeyBlob` | 作成した鍵 (公開部と秘密部)。ロード、使用、バイト配列への保存ができます。 |
| `Template` | 新しい鍵の種類と属性を記述する TPM 公開テンプレート。 |
| `Session` | TPM 認可セッション。パラメータ暗号化付きの HMAC セッションに使用します。 |
| `Csr` | サブジェクト、鍵用途、カスタム拡張を保持する証明書署名要求 (CSR) ヘルパー。 |
| `WolfTpm2Exception` | ネイティブ呼び出しが失敗したときにスローされる例外。 |
| `Status` | 主な戻りコードの列挙型: `TPM_RC_SUCCESS`、`TPM_RC_HANDLE`、`TPM_RC_NV_UNAVAILABLE`、`TPM_RC_SIGNATURE`、`BAD_FUNC_ARG`、`NOT_COMPILED_IN`。 |

このファイルには、ネイティブの値に対応する列挙型も定義されています。`TPM2_Object` (`sensitiveDataOrigin`、`userWithAuth`、`decrypt`、`sign`、`noDA` などのオブジェクト属性ビット)、`TPM2_Alg` (`RSA`、`ECC`、`SHA256`、`RSASSA`、`CFB`、`XOR`、`NULL` など)、`TPM2_ECC` (曲線)、`SE` (セッションタイプ)、`SESSION_mask`、`TPM_RH` (`OWNER`、`ENDORSEMENT`、`PLATFORM` などの階層)、`X509_Format` (`PEM` または `DER`) です。

### Device の存続期間

`Device` は `IDisposable` を実装しています。コンストラクタはネイティブの `wolfTPM2_New()` を呼び出し、これは TPM の初期化も行うため、新しい `Device` はそのまま使用できます。`Dispose()` は `wolfTPM2_Free()` を呼び出してポインタをクリアします。呼び忘れた場合はファイナライザが同じ後処理を行いますが、デバイスは `using` ステートメントで囲むか、自分で `Dispose()` を呼び出してください。

`Key`、`KeyBlob`、`Template`、`Session`、`Csr` も同じパターンです。コンストラクタがネイティブオブジェクトを確保し、`Dispose()` が解放します。解放呼び出しのネイティブ戻り値は無視されます。

`Device.Ref` はネイティブのデバイスポインタを返します。`Device` には次の定数もあります: `MAX_KEYBLOB_BYTES` (2048)、`MAX_TPM_BUFFER` (2048)、`INVALID_DEVID` (-2)。最初の 2 つはテストで使用するバッファサイズであり、プラットフォームによってはより大きな値が必要になる場合があります。

### エラーと戻り値

ほとんどのメソッドは `int` を返し、失敗時には `WolfTpm2Exception` をスローします。通常のケースでは戻り値を確認する必要はありません。例外には、ネイティブの戻りコードを持つ `ErrorCode` プロパティがあります。`Message` には、ネイティブ関数名、16 進数のコード、`TPM2_GetRCString` が返すテキストが含まれます。`Device.GetErrorString(int)` と `Device.GetErrorString(Status)` は、任意のコードに対して同じテキストを返します。

一部のメソッドは、特定のコードを致命的ではないものとして扱い、スローせずに返します。

- `ReadPublicKey` は、ハンドルにオブジェクトが存在しない場合に `TPM_RC_HANDLE` を返します。
- `StoreKey` は `TPM_RC_NV_UNAVAILABLE` を返します。
- `VerifyHashScheme` は、署名が一致しない場合に `TPM_RC_SIGNATURE` を返します。
- `Csr.SetCustomExtension` は、ネイティブライブラリが対応なしでビルドされている場合に `NOT_COMPILED_IN` を返します。

データを生成するメソッドは、成功時に正のサイズを返します: `KeyBlob.GetKeyBlobAsBuffer`、`Device.RsaEncrypt`、`Device.RsaDecrypt`、`Device.SignHashScheme`、`Device.GenerateCSR`、`Csr.MakeAndSign`。`UnloadHandle` はネイティブ関数を直接呼び出し、スローせずにそのコードを返します。

### 鍵、キーブロブ、セッション

- `Key` は、`CreateSRK`、`CreatePrimaryKey`、`ReadPublicKey`、`LoadRsaPublicKey`、`LoadRsaPrivateKey`、`ImportRsaPrivateKey` のいずれかで設定されます。`GetHandle()` はネイティブのハンドルポインタを返し、`SetKeyAuthPassword` は鍵のパスワードを設定します。
- `KeyBlob` は、親の `Key` と `Template` を指定した `CreateKey` で設定し、`LoadKey` でロードします。`GetKeyBlobAsBuffer` でエクスポートするとディスクに保存でき、別のプロセスで `SetKeyBlobFromBuffer` により復元できます。復元後は、再度 `LoadKey` でロードし、使用前に `SetKeyAuthPassword` を呼び出してください。
- `Device.StoreKey` と `Device.DeleteKey` は、`TPM_RH.OWNER` などの階層のもとで、鍵またはキーブロブを永続ストレージ (NV) に移したり削除したりします。
- ロードされた TPM オブジェクトは、解放するまで TPM 内にロードされたままです。使い終わったら、`Key`、`KeyBlob`、`Session` を指定して `Device.UnloadHandle` を呼び出してください。`Dispose()` が解放するのは、マネージドのラッパーとそのネイティブメモリだけです。
- `Session` は `StartAuth(device, parentKey, encDecAlg)` で開始します。`encDecAlg` は `TPM2_Alg.NULL`、`CFB`、`XOR` のいずれかです。HMAC セッションを開始し、認可スロット 1 (または `Session(int index)` で指定したインデックス) に割り当て、パラメータ暗号化を有効にします。終了するには `StopAuth(device)` を呼び出します。`Device.StartSession`、`SetAuthSession`、`ClearAuthSession` は、その内部で使われる低レベルの呼び出しです。

### Template と Csr

`Template` はネイティブの鍵テンプレートを設定します。`GetKeyTemplate_RSA`、`GetKeyTemplate_ECC`、`GetKeyTemplate_Symmetric`、EK、SRK、AIK 用のバリアント (`GetKeyTemplate_RSA_EK`、`GetKeyTemplate_ECC_EK`、`GetKeyTemplate_RSA_SRK`、`GetKeyTemplate_ECC_SRK`、`GetKeyTemplate_RSA_AIK`、`GetKeyTemplate_ECC_AIK`)、`SetKeyTemplate_Unique` があります。

証明書要求を 1 回の呼び出しで作成するには、サブジェクト文字列、鍵用途文字列、`X509_Format` を指定して `Device.GenerateCSR` を使用します。より細かく制御するには、`SetSubject`、`SetKeyUsage`、`SetCustomExtension` で `Csr` を構築し、`MakeAndSign` を呼び出します。拡張版のオーバーロードで `selfSign` 引数に 0 以外を指定すると、要求ではなく自己署名証明書が得られます。

### その他の Device メソッド

`SelfTest`、`GetRandom`、`RsaEncrypt`、`RsaDecrypt`、`SignHashScheme`、`VerifyHashScheme`、`GetHandleValue` も `Device` にあります。各パラメータについては `wolfTPM.cs` の XML コメントを参照してください。

### 使用例

この例では、ストレージルート鍵を作成し、その配下に RSA 鍵を作成してロードし、ダイジェストに署名して署名を検証します。`wolfTPM-tests.cs` で使われているパターンに従っています。

```csharp
using System;
using wolfTPM;

class Example
{
    static void Main()
    {
        using (Device device = new Device())
        using (Key srk = new Key())
        using (KeyBlob blob = new KeyBlob())
        using (Template template = new Template())
        {
            try
            {
                device.SelfTest();
                device.CreateSRK(srk, TPM2_Alg.RSA, "StorageKeyAuth");

                template.GetKeyTemplate_RSA((ulong)(
                    TPM2_Object.sensitiveDataOrigin |
                    TPM2_Object.userWithAuth |
                    TPM2_Object.decrypt |
                    TPM2_Object.sign |
                    TPM2_Object.noDA));

                device.CreateKey(blob, srk, template, "MyKeyAuth");
                device.LoadKey(blob, srk);

                byte[] digest = new byte[32];
                device.GetRandom(digest);

                byte[] sig = new byte[256];
                int sigSz = device.SignHashScheme(blob, digest, sig,
                    TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
                Console.WriteLine("Signature is {0} bytes", sigSz);

                int rc = device.VerifyHashScheme(blob, sig, digest,
                    TPM2_Alg.RSASSA, TPM2_Alg.SHA256);
                Console.WriteLine(rc == (int)Status.TPM_RC_SUCCESS ?
                    "Signature verified" : "Signature invalid");

                device.UnloadHandle(blob);
                device.UnloadHandle(srk);
            }
            catch (WolfTpm2Exception e)
            {
                Console.WriteLine("TPM error: " + e.Message);
            }
        }
    }
}
```

## 関連項目

- [SWTPM](system-interfaces.md)
- [Build Options](build-options.md)
- [Rust Wrapper](rust-wrapper.md)
