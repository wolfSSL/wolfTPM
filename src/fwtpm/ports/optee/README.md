# fwTPM on OP-TEE

The wolfTPM fwTPM running as an OP-TEE trusted application, with the TPM 2.0
command processor in the secure world and the client in the normal world.

Platform independent: these two sources need only the TEE Internal Core API
and OP-TEE secure storage. A board port supplies `user_ta_header_defines.h`
(UUID, flags, stack and heap sizes), the wolfCrypt platform shims and the
build, sign and deploy steps.

| File | Role |
|------|------|
| `wolftpm/fwtpm/fwtpm_optee.h` | The trusted application's UUID, the command IDs shared with the normal-world client, and the NV HAL and clock HAL declarations |
| `fwtpm_optee_ta.c` | `TA_*EntryPoint` functions; one invocation carries one whole TPM command |
| `fwtpm_optee_nv.c` | NV journal on OP-TEE secure storage, with the journal integrity key derived from the hardware unique key |

## Transport

`FWTPM_ProcessCommand` takes a command buffer and returns a response buffer,
which is exactly the shape of `TA_InvokeCommandEntryPoint`, so no IO HAL and
no TIS layer is involved. `FWTPM_IO_ServerLoop` and `FWTPM_TIS_ServerLoop`
both block and cannot be used in a trusted application, so `fwtpm_io.c`,
`fwtpm_tis.c`, `fwtpm_tis_shm.c` and `fwtpm_main.c` are left out of the
build.

Both directions are staged through static buffers of `FWTPM_MAX_COMMAND_SIZE`.
The response buffer must be that large whatever the client's capacity, and
staging the command as well means the normal world cannot change it after it
has been parsed.

`locality` is fixed at `FWTPM_OPTEE_LOCALITY` and never taken from the
client: it is stored verbatim into the command context without validation.

## NV storage

Secure storage is byte addressable and fully rewritable, so the journal runs
in its default mode with `appendOnly` and `writeAlign` left at 0. The
append-only build option is for write-once flash and is not needed here.

A read past the end of the stream is reported as erased (`0xFF`), which is how
the journal recognizes unwritten NV and decides to generate fresh seeds on
first boot.

`get_integrity_key` asks the system PTA for a key derived from the hardware
unique key and bound to the TA UUID. Platforms built without the system PTA
fall back to a random key in its own secure storage object. Secure storage is
itself hardware-unique-key encrypted and TA bound, so the journal MAC is
defense in depth.

## wolfCrypt platform layer

None is needed here. wolfSSL maps `XMALLOC`, `XFREE` and `XREALLOC` onto
`TEE_Malloc`, `TEE_Free` and `TEE_Realloc`, and seeds its DRBG from
`TEE_GenerateRandom`, whenever `WOLFSSL_OPTEE` is defined. A port does not
supply shims or set `XMALLOC_OVERRIDE`.

Where wolfCrypt is not compiled in at all (`WOLFTPM2_NO_WOLFCRYPT`),
`wolftpm/tpm2_types.h` does the same for its own `XMALLOC` and `XFREE`.
`WOLFTPM2_NO_HEAP` still wins there and leaves both undefined.

## Required wolfCrypt options

A trusted application is built from a `user_settings.h` with no configure
step, so nothing checks the wolfCrypt configuration the way wolfTPM's
configure does. The fwTPM needs, beyond the obvious RSA, ECC, AES-CFB,
HMAC/HKDF, SHA-1/2/3 and ASN.1:

| Option | Why |
|--------|-----|
| `WOLFSSL_OPTEE` | names the environment, and brings in the heap and RNG mapping above |
| `WOLFSSL_KEY_GEN` | the TPM generates its own primary keys |
| `WC_RSA_PSS` | TPM 2.0 RSA signing schemes |
| `WC_RSA_NO_PADDING` | raw RSA; without it those operations return `TPM_RC_SCHEME` |
| `WOLFSSL_AES_CFB`, `WOLFSSL_AES_DIRECT` | TPM 2.0 parameter encryption |
| `WOLFSSL_NO_DER_TO_PEM` | `WOLFSSL_KEY_GEN` otherwise pulls in `wc_DerToPemEx`, which needs a `strncat` libutee does not provide |
| `USE_WOLF_STRCASECMP`, `USE_WOLF_STRNCASECMP` | libutee has neither |
| `WOLFSSL_HAVE_MLDSA`, `WOLFSSL_HAVE_MLKEM` | the v1.85 post-quantum commands |

`WOLFSSL_OPTEE` is not optional: the trusted application toolchain is a Linux
cross compiler and predefines `__unix__`, so without it wolfCrypt compiles
descriptor and socket code a trusted application cannot provide.

OP-TEE's `compiler.h` defines a `fallthrough` macro. wolfCrypt only notices
it if `compiler.h` was included first and otherwise settles on
`__attribute__((fallthrough))`, which then expands through OP-TEE's macro and
nests the attribute inside itself, so define `FALL_THROUGH` explicitly.

## Client

Build wolfTPM with `WOLFTPM_OPTEE` to reach the TA over `libteec`. One
`TEEC_InvokeCommand` maps onto one `FWTPM_ProcessCommand`, following the
`WOLFTPM_SWTPM` whole-command pattern rather than emulating TIS registers,
which would cost a world switch per register access.

One session per process: the client holds the TEE session in file scope, so
two `TPM2_CTX` in one process share it and `TPM2_Cleanup` on either closes it.
The other reconnects on its next command, but the trusted application flushes
transient objects on session close, so transient handles do not survive. Create
and use a key in one context, or make the handle persistent with
`TPM2_EvictControl`.

## UUID

OP-TEE identifies a trusted application by UUID, and the same value has to
appear in the trusted application, in the signed binary's filename and in the
client, which are built separately. `WOLFTPM_OPTEE_TA_UUID_STR` and the `_P1`
to `_P4` macros beside it in `wolftpm/fwtpm/fwtpm_optee.h` are the one
definition; the client builds `WOLFTPM_OPTEE_TA_UUID` from them and a board
port generates its `TA_UUID` and binary name from them. A mismatch appears
only at run time, as `TEEC_OpenSession` returning `0xffff0008`.

## Build order

    XMEMSET(&ctx, 0, sizeof(ctx));
    FWTPM_OPTEE_NV_SetHAL(&ctx, &nv);   /* before FWTPM_Init */
    FWTPM_Clock_SetHAL(&ctx, FWTPM_OPTEE_Clock_GetMs, NULL);  /* optional */
    FWTPM_Init(&ctx);

## Reference port

NVIDIA Jetson Orin: see `NVIDIA/fwtpm-jetson-optee` in
[wolftpm-examples](https://github.com/wolfSSL/wolftpm-examples).
