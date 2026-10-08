# ベンチマーク

このページでは、`examples/bench/bench` プログラムで測定した、対応 TPM 2.0 デバイスにおける一般的な操作の処理速度と、SEALSQ QVault シリコンによる初のポスト量子暗号の測定値を示します。

## これらの数値について

これらは、異なるホストボードとバス速度で実機から取得した代表的な測定結果です。結果は TPM のファームウェアバージョン、バスクロック、ホストプラットフォーム、ビルドオプションによって変動するため、目安として扱い、実際の環境で `./examples/bench/bench` を実行してください。

## デバイス別 TPM 2.0 ベンチマーク

1 操作あたりの平均レイテンシ (ミリ秒、小さいほど良い)。RSA-2048 の鍵生成は、プロビジョニング時に 1 回だけ発生するコストです。

| デバイス | バス | RSA-2048 鍵生成 | RSA-2048 秘密鍵演算 | ECDSA P-256 署名 | ECDSA P-256 検証 |
|---|---|---|---|---|---|
| Infineon OPTIGA SLB9670 | SPI, 43 MHz | 2196.2 | 163.2 | 68.9 | 113.5 |
| Infineon OPTIGA SLB9672 | SPI, 43 MHz | 1567.7 | 77.0 | 35.6 | 24.1 |
| Infineon OPTIGA SLB9673 | I2C, 400 kHz | 1910.6 | 168.1 | 72.1 | 57.9 |
| STMicro ST33KTPM2XSPI | SPI, 33 MHz | 1944.1 | 90.8 | 25.3 | 36.5 |
| STMicro ST33TPHF2XSPI | SPI, 33 MHz | 7455.0 | 247.8 | 42.3 | 74.0 |
| Microchip ATTPM20 | SPI, 33 MHz | 5275.9 | 117.7 | 58.7 | 43.0 |
| Nations Z32H330 | SPI, 33 MHz | 2183.8 | 133.2 | 23.4 | 36.8 |
| Nations NS350 | SPI, 33 MHz | 2378.9 | 51.7 | 16.8 | 21.9 |
| Nuvoton NPCT650 | 記載なし | 4479.2 | 540.9 | 190.1 | 265.2 |
| Nuvoton NPCT750 | SPI, 43 MHz | 3408.7 | 70.3 | 56.4 | 39.2 |
| NVIDIA Jetson Orin fTPM (OP-TEE) | `/dev/tpmrm0` | 736.4 | 11.9 | 45.1 | 31.7 |

README に記載された ST33TPHF2XSPI の RSA 鍵生成の測定は 1 回の操作のみで実行されているため、この値は表の中で最も信頼性が低くなります。

Infineon OPTIGA SLB9672 を 43 MHz で動作させた場合の `./examples/bench/bench` の出力例を示します。

```
./examples/bench/bench
TPM2 Benchmark using Wrapper API's
	Use Parameter Encryption: NULL
Loading SRK: Storage 0x81000200 (282 bytes)
RNG                 24 KB took 1.070 seconds,   22.429 KB/s
Benchmark symmetric AES-128-CBC-enc not supported!
Benchmark symmetric AES-128-CBC-dec not supported!
Benchmark symmetric AES-256-CBC-enc not supported!
Benchmark symmetric AES-256-CBC-dec not supported!
Benchmark symmetric AES-128-CTR-enc not supported!
Benchmark symmetric AES-128-CTR-dec not supported!
Benchmark symmetric AES-256-CTR-enc not supported!
Benchmark symmetric AES-256-CTR-dec not supported!
AES-128-CFB-enc     86 KB took 1.001 seconds,   85.890 KB/s
AES-128-CFB-dec     88 KB took 1.020 seconds,   86.267 KB/s
AES-256-CFB-enc     86 KB took 1.023 seconds,   84.073 KB/s
AES-256-CFB-dec     86 KB took 1.019 seconds,   84.370 KB/s
SHA1                88 KB took 1.021 seconds,   86.155 KB/s
SHA256              86 KB took 1.015 seconds,   84.717 KB/s
SHA384              90 KB took 1.007 seconds,   89.405 KB/s
RSA     2048 key gen       10 ops took 15.677 sec, avg 1567.678 ms, 0.638 ops/sec
RSA     2048 Public       110 ops took 1.000 sec, avg 9.095 ms, 109.951 ops/sec
RSA     2048 Private       14 ops took 1.078 sec, avg 76.996 ms, 12.988 ops/sec
RSA     2048 Pub  OAEP     51 ops took 1.012 sec, avg 19.838 ms, 50.408 ops/sec
RSA     2048 Priv OAEP     12 ops took 1.053 sec, avg 87.738 ms, 11.398 ops/sec
ECC      256 key gen        8 ops took 1.088 sec, avg 135.956 ms, 7.355 ops/sec
ECDSA    256 sign          29 ops took 1.033 sec, avg 35.621 ms, 28.073 ops/sec
ECDSA    256 verify        42 ops took 1.013 sec, avg 24.114 ms, 41.470 ops/sec
ECDHE    256 agree         16 ops took 1.055 sec, avg 65.948 ms, 15.164 ops/sec
```

モードに対応していないデバイスでは、そのモードについて "not supported" と出力されます。

## ポスト量子暗号 (SEALSQ QVault)

これらの数値は、SPI 経由で SEALSQ QVault TPM を駆動する Raspberry Pi 5 上で `examples/bench/bench` を使って測定しました。SEALSQ は、この製品をシリコンとして実現された初のポスト量子暗号対応 TPM と位置付けています。

| 操作 | 平均レイテンシ | スループット |
|---|---|---|
| ML-DSA-65 鍵生成 | 2044.7 ms | 0.49 ops/s |
| ML-DSA-65 署名 | 581.0 ms | 1.72 ops/s |
| ML-DSA-65 検証 | 163.1 ms | 6.13 ops/s |
| ML-KEM-768 鍵生成 | 800.8 ms | 1.25 ops/s |
| ML-KEM-768 カプセル化 | 211.8 ms | 4.72 ops/s |
| ML-KEM-768 デカプセル化 | 425.5 ms | 2.35 ops/s |

鍵生成はプロビジョニング時に 1 回だけ発生するコストです。上記の ECDSA の値は、異なる TPM、ホストボード、バス、ファームウェアで取得したものであるため、これらの ML-DSA の値と同一条件での比較にはなりません。ECDSA と PQC のレイテンシを比較するには、同じ TPM、ホスト、バス、ビルドで両方について `./examples/bench/bench` を実行してください。

## 関連項目

- [テストと CI](testing.md)
- [引用文献](cited-sources.md)
- [リリースノート](release-notes.md)
