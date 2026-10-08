# fwTPM SPDM Responder

The fwTPM ships an SPDM 1.3 responder, so the full SPDM stack can be exercised against a TPM that has no silicon behind it. It supports both the TCG raw public key handshake (GET_PUBK and GIVE_PUB, no certificates) and the DSP0274 pre-shared key (PSK) handshake. This lets you develop and test SPDM-secured TPM communication in CI or on a workstation before real hardware is available. For the library-wide SPDM view, see [SPDM](../spdm.md).

## How It Works

When SPDM is on, the responder sits above the existing transport HAL and dispatches TCG-framed messages into the SPDM state machine. The two message tags are:

| Tag | Meaning |
|-----|---------|
| `0x8101` | Clear (unsecured) SPDM message |
| `0x8201` | Secured SPDM message |

Plaintext TPM frames fall through to the regular command dispatcher until the requester issues `SPDMONLY LOCK`. After that, only `TPM2_GetCapability` is allowed through in plaintext, which matches the behavior of Nuvoton and Nations silicon.

## Building

Build with `--enable-fwtpm --enable-spdm` plus at least one of `--enable-tcg` or `--enable-psk`:

```sh
./configure --enable-fwtpm --enable-swtpm --enable-spdm --enable-tcg --enable-psk
make
```

## Starting the Responder

Start the server in one of three modes:

```sh
SPDM_PSK=dbc2192291d807742441b963f6712841f7697e2e39c45931f3abc53658c8b9338bd3561cab5d90cf9e493295bb5bd6b2c455e0fd19392e0ce4f3433cbcfc7047
./src/fwtpm/fwtpm_server --spdm-tcg                              # TCG raw public key handshake
./src/fwtpm/fwtpm_server --spdm-psk --spdm-psk-hex "$SPDM_PSK"   # PSK handshake
./src/fwtpm/fwtpm_server --no-spdm                               # plaintext only (default)
```

The responder accepts a PSK of up to 64 bytes (128 hex characters) and rejects only an empty PSK or one longer than that; the exact 64-byte requirement applies to Nations hardware provisioning, not to this responder. The value above is the test value used by `spdm_test.sh`. For a manual PSK test, give the requester the same value, for example `spdm_ctrl --psk "$SPDM_PSK"`.

## Responder Identity Key

The responder generates a fresh P-384 identity keypair at startup. It is used to sign `GET_PUBK` and `KEY_EXCHANGE`. The private key never leaves `fwtpm_server` memory, and the stack copy is zeroed with `wc_ForceZero` after it is handed to the responder context.

In TCG mode, the server prints the public half during startup so the local test harness can pass it to the requester through the responder-key pinning API.

!!! warning
    This printed public key is a test bootstrap channel. It is not a substitute for authenticated device provisioning, and it is not a trust anchor for hardware responders.

## Testing

End-to-end coverage uses the same script that drives real silicon:

```sh
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-tcg
./examples/spdm/spdm_test.sh ./examples/spdm/spdm_ctrl fwtpm-psk
```

CI exercises 7 build-only configure permutations plus the two end-to-end modes on `ubuntu-latest` through `spdm-test.yml`, against the fwTPM SPDM responder.

## See Also

- [Overview](overview.md)
- [Building](building.md)
- [Usage](usage.md)
- [Post-Quantum Support](post-quantum.md)
- [SPDM (library-wide)](../spdm.md)
