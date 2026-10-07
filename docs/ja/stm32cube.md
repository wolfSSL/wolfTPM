# STM32CubeIDE

wolfTPM は STM32 Cube Pack の `I-CUBE-wolfTPM.pack` として提供されており、https://www.wolfssl.com/files/ide/I-CUBE-wolfTPM.pack からダウンロードできます。このパックは、wolfCrypt ライブラリへの依存がオプションですが、推奨されています。ファイルは wolfTPM のソースツリー内の `IDE/STM32CUBE` にあります。

!!! note
    このページは短く、後日拡充される予定です。

## セットアップ

1. wolfSSL の STM32Cube ガイド https://github.com/wolfSSL/wolfssl/blob/master/IDE/STM32Cube/README.md に従って、ST プロジェクトに wolfCrypt ライブラリをセットアップします。wolfTPM のユニットテストを実行するには、エントリ関数の名前を `wolfCryptDemo` ではなく `wolfTPMTest` にします。
2. wolfSSL パックと同じ方法で、CubeMX を使用して wolfTPM Cube Pack をインストールします。
3. プロジェクトの `.ioc` ファイルを開き、`Software Packs` ドロップダウンメニューから `Select Components` をクリックします。`wolfTPM` パックを展開し、すべてのコンポーネントにチェックを入れます。
4. `.ioc` ファイルの `Software Packs` 設定カテゴリで wolfTPM パックをクリックし、チェックボックスをオンにしてライブラリを有効にします。
5. `Connectivity` カテゴリで、プロジェクトで使用する SPI を見つけて有効にします。
6. `Software Packs` 設定カテゴリで wolfTPM パックを開き、`Enable wolfCrypt` パラメータを True に設定します。
7. 変更を保存し、コード生成を確認するプロンプトには yes と答えます。
8. プロジェクトをビルドし、ターゲット上でユニットテストを実行します。

## 注意事項

テスト出力を確認できるように、`printf` を UART にリダイレクトしてください。wolfSSL ガイドの [STM32 printf changes](https://github.com/wolfSSL/wolfssl/tree/master/IDE/STM32Cube#stm32-printf) を参照してください。

## 関連項目

- [Building](building.md): ベアメタルのビルドオプションについて
- [System Interfaces](system-interfaces.md): STM32H5 上での UART 経由 SWTPM の例について
- [Embedded Integrations](embedded-integrations.md)
