# Testing

This page describes how to run the wolfTPM tests locally and lists the continuous integration workflows that run on the repository.

## Running tests locally

Build and run the main test suite:

```sh
./configure
make check
```

`make check` runs the unit tests, the fwTPM tests and the post-quantum (PQC) tests. The unit test sources are:

| File | Purpose |
|---|---|
| `tests/unit_tests.c` | wolfTPM library unit tests |
| `tests/fwtpm_unit_tests.c` | fwTPM command processor unit tests |
| `tests/fwtpm_hal_unit_tests.c` | fwTPM HAL unit tests |

The shell-based tests are:

| File | Purpose |
|---|---|
| `tests/fwtpm_check.sh` | Entry point used by `make check` for the fwTPM tests |
| `tests/fwtpm_da_retry.sh` | Dictionary attack and retry handling |
| `tests/pqc_mssim_e2e.sh` | Post-quantum end-to-end test |

To run the example programs against a TPM or simulator:

```sh
./examples/run_examples.sh
```

The script reads these environment variables:

| Variable | Purpose |
|---|---|
| `WOLFSSL_PATH` | Path to the wolfSSL build used by the examples |
| `WOLFCRYPT_ENABLE` | Set when wolfCrypt support is built in |
| `NO_FILESYSTEM` | Skip examples that need a filesystem |
| `ENABLE_DESTRUCTIVE_TESTS` | Also run tests that change TPM state, such as clearing it |

!!! warning
    Destructive tests modify the TPM. Do not enable them on a TPM that holds keys or data you need.

## CI workflows

The workflows live in `.github/workflows/`. The table lists the workflow name from each file.

| File | Name |
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

## See Also

- [Benchmarks](benchmarks.md)
- [SBOM and Compliance](sbom-and-compliance.md)
- [Release Notes](release-notes.md)
