# 引用文献

このページでは、本マニュアルの執筆に使用した参考文献を示します。元の序文で引用された 2 つの文献と、マニュアルが参照する仕様書の順に記載しています。

## 参考文献

1. Wikipedia contributors. (2018, May 30). Trusted Platform Module. In _Wikipedia, The Free Encyclopedia_. Retrieved 22:46, June 20, 2018.
2. Arthur W., Challener D., Goldman K. (2015). Platform Configuration Registers. In: _A Practical Guide to TPM 2.0_. Apress, Berkeley, CA.

## 仕様書

| 仕様書 | 発行団体 | 適用箇所 |
|---|---|---|
| TPM 2.0 Library Specification, versions 1.38, 1.59, 1.84 and 1.85 | Trusted Computing Group (TCG) | wolfTPM と fwTPM が実装する TPM 2.0 のコマンドセット、構造体、動作。バージョン 1.85 でポスト量子暗号コマンドが追加されました。 |
| FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | NIST | ポスト量子暗号の鍵カプセル化 (ML-KEM-768)。 |
| FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA) | NIST | ポスト量子暗号の署名 (ML-DSA-65)。 |
| DSP0274, Security Protocol and Data Model (SPDM) Specification | DMTF | 対応する TPM モジュールおよび fwTPM で使用される SPDM セキュアトランスポート。 |

## 関連項目

- [ベンチマーク](benchmarks.md)
- [リリースノート](release-notes.md)
- [API リファレンス](api-reference.md)
