# fwTPM OP-TEE port tests

Host tests for the fwTPM OP-TEE trusted application port in `src/fwtpm/ports/optee`. They run the port against a mock of the TEE Internal Core API that keeps secure storage in RAM and can inject TEE failures (system PTA missing, key object unreadable, storage unavailable).

## Port tests

`tests/fwtpm_optee_port.test` is built by `make check` in any fwTPM configuration. It stubs the fwTPM core and tests the port itself: NV integrity key selection, secure storage access, session to client mapping and command/response buffer handling.

## Core tests

`optee_core.mk` links the port with the real fwTPM core and wolfCrypt compiled from source as `WOLFSSL_OPTEE`, and drives it through the TA entry points. It tests per-session ownership of transient objects and the NV journal in secure storage across TA instances. It needs a wolfSSL source tree with `WOLFSSL_OPTEE` support. Run it from the wolfTPM root:

    make -f tests/optee/optee_core.mk WOLFSSL=../wolfssl check

The `optee-mock` CI job runs it on pushes and pull requests that touch the fwTPM, against the wolfSSL commit pinned in `.github/workflows/optee-mock.yml`, and nightly against wolfSSL master.

## Files

- `tee_internal_api.h`, `tee_internal_api_extensions.h`, `pta_system.h` - mock OP-TEE headers, found by the port under their OP-TEE names
- `mock_tee.c`, `mock_tee.h` - mock TEE implementation and fault injection
- `fwtpm_optee_port_tests.c` - port tests with the fwTPM core stubbed
- `optee_core_tests.c`, `optee_core.mk`, `user_settings.h` - core tests and their build
