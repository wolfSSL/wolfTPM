# fwTPM の SPDM レスポンダ

fwTPM には SPDM 1.3 レスポンダが同梱されているため、シリコンの裏付けがない TPM に対して SPDM スタック全体を検証できます。TCG の raw 公開鍵ハンドシェイク (GET_PUBK と GIVE_PUB、証明書なし) と、DSP0274 の事前共有鍵 (PSK) ハンドシェイクの両方をサポートしています。これにより、実際のハードウェアが利用可能になる前に、CI やワークステーション上で SPDM で保護された TPM 通信を開発およびテストできます。ライブラリ全体の SPDM に関する概要については、[SPDM](../spdm.md)を参照してください。

## 動作の仕組み

SPDM が有効な場合、レスポンダは既存のトランスポート HAL の上位に位置し、TCG フレーミングされたメッセージを SPDM ステートマシンへディスパッチします。2 つのメッセージタグは次のとおりです。

| タグ | 意味 |
|-----|---------|
| `0x8101` | クリア (保護されていない) SPDM メッセージ |
| `0x8201` | セキュア SPDM メッセージ |

平文の TPM フレームは、リクエスタが `SPDMONLY LOCK` を発行するまで、通常のコマンドディスパッチャに渡されます。その後は `TPM2_GetCapability` のみが平文で許可され、これは Nuvoton および Nations のシリコンの動作と一致します。

## ビルド

`--enable-fwtpm --enable-spdm` に加えて、`--enable-tcg` または `--enable-psk` の少なくとも一方を指定してビルドします。

```sh
./configure --enable-fwtpm --enable-swtpm --enable-spdm --enable-tcg --enable-psk --enable-nuvoton --enable-nations
make
```

## レスポンダの起動

サーバーは 3 つのモードのいずれかで起動します。

```sh
SPDM_PSK=dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047
./src/fwtpm/fwtpm_server --spdm-tcg                              # TCG raw public key handshake
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK"   # PSK handshake
./src/fwtpm/fwtpm_server --no-spdm                               # plaintext only (default)
```

レスポンダは、空ではなく最大 64 バイト (16 進数 128 文字) の PSK を受け付けます。64 バイトちょうどであることが求められるのは Nations ハードウェアのプロビジョニングであり、このレスポンダではありません。上記の値は `spdm_test.sh` で使用されるテスト値です。手動で PSK をテストする場合は、リクエスタにも同じ値を指定してください (例: `spdm_ctrl --psk "$SPDM_PSK"`)。

## レスポンダの ID 鍵

レスポンダは起動時に新しい P-384 の ID 鍵ペアを生成します。これは `GET_PUBK` と `KEY_EXCHANGE` への署名に使用されます。秘密鍵が `fwtpm_server` のメモリの外に出ることはなく、スタック上のコピーは、レスポンダコンテキストに渡された後に `wc_ForceZero` でゼロ化されます。

TCG モードでは、サーバーは起動時に公開鍵側を出力します。これにより、ローカルのテストハーネスが、レスポンダ鍵ピンニング API を通じてリクエスタへ渡せます。

!!! warning
    この出力される公開鍵は、テスト用のブートストラップチャネルです。認証されたデバイスのプロビジョニングの代わりにはならず、ハードウェアレスポンダ向けのトラストアンカーでもありません。

## テスト

エンドツーエンドのカバレッジには、実際のシリコンを駆動するのと同じスクリプトを使用します。

```sh
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-tcg
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-psk
```

CI は、`spdm-test.yml` を通じて `ubuntu-latest` 上で、7 つのビルドのみの configure の組み合わせと、2 つのエンドツーエンドモードを、fwTPM の SPDM レスポンダに対して実行します。

## 関連項目

- [概要](overview.md)
- [ビルド](building.md)
- [使用方法](usage.md)
- [ポスト量子サポート](post-quantum.md)
- [SPDM (ライブラリ全体)](../spdm.md)
