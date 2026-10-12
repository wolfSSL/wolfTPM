# Cited Sources

This page lists the references used while writing this manual: the two works cited in the original introduction, followed by the specifications the manual refers to.

## References

1. Wikipedia contributors. (2018, May 30). Trusted Platform Module. In _Wikipedia, The Free Encyclopedia_. Retrieved 22:46, June 20, 2018.
2. Arthur W., Challener D., Goldman K. (2015). Platform Configuration Registers. In: _A Practical Guide to TPM 2.0_. Apress, Berkeley, CA.

## Specifications

| Specification | Body | Where it applies |
|---|---|---|
| TPM 2.0 Library Specification, versions 1.38, 1.59, 1.84 and 1.85 | Trusted Computing Group (TCG) | The TPM 2.0 command set, structures and behavior that wolfTPM and the fwTPM implement. Version 1.85 adds the post-quantum commands. |
| FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM) | NIST | Post-quantum key encapsulation (ML-KEM-768). |
| FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA) | NIST | Post-quantum signatures (ML-DSA-65). |
| DSP0274, Security Protocol and Data Model (SPDM) Specification | DMTF | The SPDM secured transport used with supported TPM modules and the fwTPM. |

## See Also

- [Benchmarks](benchmarks.md)
- [Release Notes](release-notes.md)
- [API Reference](api-reference.md)
