# API Reference

wolfTPM exposes three layers of headers. This page explains which one to start with. The function-level reference is generated from the header comments with Doxygen and appears on the pages that follow in this section.

## Wrapper API

The wrapper API is declared in `wolftpm/tpm2_wrap.h`. All of its functions are named `wolfTPM2_*`. It hides command sequencing, session handling, parameter encryption and key blob management behind a small set of calls, and it is the recommended starting point for applications. Key creation, loading, signing, sealing and NV storage are covered in [Key Management](key-management.md), and quoting and PCR use in [Attestation](attestation.md).

## Native API

The native API is declared in `wolftpm/tpm2.h`. It provides the raw `TPM2_*` commands, one function per TPM 2.0 command, along with the structures and constants from the TCG specification. Use it when you need direct control over command parameters or need a command the wrapper does not cover. You build the command arguments yourself and handle sessions and authorization explicitly.

## HAL IO

`hal/tpm_io.h` declares the hardware abstraction layer used to move bytes between wolfTPM and the TPM. It is the header to read when you port wolfTPM to a new board or bus. See [HAL IO Callback](hal-io-callback.md).

## Generated Reference

The full function-level reference is generated from the header Doxygen comments and appears as the following pages in this section:

- TPM2 API
- TPM2 Wrapper API
- TPM2 Header File
- TPM2 Wrapper Header File
- TPM2 HAL IO

## See Also

- [Key Management](key-management.md)
- [Attestation](attestation.md)
- [HAL IO Callback](hal-io-callback.md)
