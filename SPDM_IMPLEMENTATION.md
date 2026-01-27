# wolfTPM SPDM Implementation Tracking

## Target Hardware
- **TPM**: Nuvoton NPCT75x (Fw 7.2.5.1)
- **Interface**: SPI (/dev/spidev0.0, 33 MHz)
- **Platform**: Raspberry Pi (aarch64 Linux)
- **TPM Caps**: 0x30000697, Did 0x00fc, Vid 0x1050, Rid 0x01

## Reference Documents
- DMTF DSP0274: SPDM v1.3.2
- TCG SPDM Binding for Secure Communication v1.0
- TCG TPM 2.0 Library Specification v1.84
- **Nuvoton TPM SPDM Public Key Authentication Guidance Rev 1.11** (primary reference)

## Algorithm Set B (Fixed, No Negotiation)
- Signing: ECDSA P-384
- Hash: SHA-384
- Key Exchange: ECDHE P-384
- AEAD: AES-256-GCM
- No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS needed (Nuvoton specific)

## Architecture

```
Application
    |
wolfTPM2 Wrapper API (tpm2_wrap.c)  -- wolfTPM2_Spdm* functions
    |
SPDM Session Manager (tpm2_spdm.c) -- TCG framing, vendor commands
    |
SPDM Backend Abstraction            -- swappable: libspdm or wolfSPDM
    |
TPM2_SendRawBytes (tpm2.c)          -- raw SPI FIFO I/O
    |
TIS Layer (tpm2_tis.c)              -- SPI HAL
```

## Files

### New Files
| File | Purpose | Status |
|------|---------|--------|
| `wolftpm/tpm2_spdm.h` | SPDM public API, types, context, backend abstraction | Created |
| `src/tpm2_spdm.c` | TCG message framing, session manager, vendor commands, I/O callback | Created |
| `src/tpm2_spdm_libspdm.c` | libspdm backend implementation (compile-time selectable) | Created (untested) |
| `examples/spdm/spdm_demo.c` | Interactive SPDM demo with CLI options | Created |

### Modified Files
| File | Changes | Status |
|------|---------|--------|
| `wolftpm/tpm2.h` | SPDM constants, TCG binding tags, vendor codes, NTC2 SPDM defines | Done |
| `wolftpm/tpm2_wrap.h` | wolfTPM2_Spdm* wrapper API declarations, spdmCtx in WOLFTPM2_DEV | Done |
| `src/tpm2.c` | TPM2_SendRawBytes implementation, NTC2 AUTODETECT guards | Done |
| `src/tpm2_wrap.c` | wolfTPM2_Spdm* wrapper implementations | Done |
| `src/tpm2_packet.c` | Export TPM2_Packet_SwapU32 | Done |
| `wolftpm/tpm2_packet.h` | Declare TPM2_Packet_SwapU32 | Done |
| `configure.ac` | Fix SPDM define duplication, add --with-libspdm | Done |
| `src/include.am` | Add tpm2_spdm.c, tpm2_spdm_libspdm.c | Done |
| `wolftpm/include.am` | Add tpm2_spdm.h | Done |
| `examples/spdm/include.am` | Add spdm_demo target | Done |
| `examples/spdm/tcg_spdm.c` | Update guards | Done |
| `tests/unit_tests.c` | Add SPDM test stubs | Done |

---

## TCG SPDM Binding Header Format (CRITICAL)

Per Nuvoton SPDM Guidance Rev 1.11, the TCG binding header is **16 bytes**:

```
Offset  Size  Endian  Field
0       2     BE      Tag (0x8101 clear, 0x8201 secured)
2       4     BE      Size (total message including header)
6       4     BE      Connection Handle (0x00000000)
10      2     BE      FIPS Service Indicator (0x0000 or 0x0001)
12      4     --      Reserved (0x00000000)
```

**Previous bug**: Header was 10 bytes (connHandle=2, fips=1, reserved=1). Fixed.

## Vendor-Defined Message Format

```
Offset  Size  Endian  Field
0       1     --      SPDM Version (0x13 for v1.3)
1       1     --      RequestResponseCode (0xFE req, 0x7E rsp)
2       1     --      Param1
3       1     --      Param2
4       2     LE      StandardID (0x0001 = TCG)  ** LITTLE ENDIAN **
6       1     --      VendorIDLen (0x00 for TCG)
7       2     LE      ReqRspLen (payload length)  ** LITTLE ENDIAN **
9       8     --      VdCode (ASCII, 8 bytes)
17+     var   --      Payload
```

**Previous bug**: StandardID and ReqRspLen were big-endian. Fixed to little-endian.
**Previous bug**: Missing SPDM Version byte at offset 0. Fixed.

## Vendor Codes (8-byte ASCII)
| VdCode | Purpose |
|--------|---------|
| `GET_STS_` | Query SPDM status (statusType uint32 payload) |
| `GET_PUBK` | Get TPM SPDM-Identity public key |
| `GIVE_PUB` | Give host SPDM-Identity public key |
| `TPM2_CMD` | TPM command over SPDM secured session |
| `SPDMONLY` | Lock/unlock SPDM-only mode |

---

## Implementation Checklist

### Phase 1: Infrastructure (COMPLETE)
- [x] Add SPDM constants to `tpm2.h` (tags, vendor codes, algorithm IDs, NV indices)
- [x] Create `tpm2_spdm.h` with public API, types, context struct, backend abstraction
- [x] Create `tpm2_spdm.c` with TCG message framing (Build/Parse Clear/Secured)
- [x] Create `tpm2_spdm.c` vendor-defined message helpers (Build/Parse VendorDefined)
- [x] Add `TPM2_SendRawBytes` API in `tpm2.c` for raw SPI FIFO communication
- [x] Create default SPDM I/O callback (`spdm_default_io_callback`) using `TPM2_SendRawBytes`
- [x] Add SPDM context pointer to `WOLFTPM2_DEV` struct
- [x] Add wrapper API (`wolfTPM2_SpdmInit/Cleanup/Connect/Disconnect/...`) in `tpm2_wrap.c`
- [x] Wire `wolfTPM2_SpdmInit` to set up I/O callback with `&dev->ctx` as userCtx
- [x] Fix `configure.ac` SPDM define duplication
- [x] Add build system entries (`include.am` files)

### Phase 2: TCG Header Format Fix (COMPLETE)
- [x] Fix `SPDM_TCG_BINDING_HEADER_SIZE` from 10 to 16
- [x] Fix `SPDM_TCG_CLEAR_HDR` struct: connectionHandle word32, fipsIndicator word16, reserved word32
- [x] Fix `SPDM_TCG_SECURED_HDR` struct: same field size corrections
- [x] Fix `SPDM_BuildClearMessage`: write 4-byte connHandle, 2-byte FIPS, 4-byte reserved
- [x] Fix `SPDM_ParseClearMessage`: read with corrected offsets
- [x] Fix `SPDM_BuildSecuredMessage`: write corrected header
- [x] Fix `SPDM_ParseSecuredMessage`: read with corrected offsets
- [x] Fix context field types: connectionHandle word32, fipsIndicator word16

### Phase 3: Vendor-Defined Message Fix (COMPLETE)
- [x] Add little-endian helpers (`SPDM_Set16LE`, `SPDM_Get16LE`)
- [x] Fix `SPDM_BuildVendorDefined`: add SPDM version byte, use LE for StandardID and ReqRspLen
- [x] Fix `SPDM_ParseVendorDefined`: account for version byte, use LE for fields
- [x] Fix `wolfTPM2_SPDM_GetStatus`: add statusType uint32 parameter (0x00000000 = "All")
- [x] Fix `wolfTPM2_SPDM_GetStatus`: proper vendor-defined response parsing with size tracking

### Phase 4: NTC2 SPDM Enable (COMPLETE)
- [x] Add NTC2 AUTODETECT guards for CFG_STRUCT, NTC2_PreConfig_In, NTC2_GetConfig_Out
- [x] Implement `wolfTPM2_SPDM_Enable` using `TPM2_NTC2_GetConfig`/`TPM2_NTC2_PreConfig`
- [x] Verify SPDM is enabled (Cfg_H=0xF0, bit 1=0 means enabled)

### Phase 5: Demo Application (COMPLETE)
- [x] Create `spdm_demo.c` with CLI: --enable, --status, --get-pubkey, --connect, --lock, --unlock, --all, --raw-test
- [x] Handle `TPM_RC_DISABLED` from `wolfTPM2_Init` (SPDM-only mode tolerance)
- [x] Raw GET_VERSION test function for protocol debugging

### Phase 6: Hardware Verification (COMPLETE for pre-session)
- [x] **GET_VERSION**: Sends 20-byte request, receives 24-byte VERSION response with SPDM v1.3
- [x] **GET_STS_**: Sends 37-byte request, receives 37-byte vendor-defined response (4-byte status payload)
- [x] **GET_PUBK**: Sends 33-byte request, receives 153-byte response with 120-byte TPMT_PUBLIC (ECDSA P-384)
- [x] Verified FIPS indicator = 0x0001 in responses (FIPS approved)
- [x] Confirmed TPM_RC_DISABLED behavior when SPDM-only mode active

### Phase 7: SPDM Session Establishment (TODO)
- [ ] Implement native KEY_EXCHANGE request builder (ECDHE P-384 ephemeral key)
- [ ] Parse KEY_EXCHANGE_RSP (verify responder signature over transcript)
- [ ] Implement GIVE_PUB vendor command (send host's SPDM-Identity pub key within handshake)
- [ ] Implement FINISH request (requester signs transcript + HMAC)
- [ ] Parse FINISH_RSP
- [ ] Derive session keys (AES-256-GCM) from ECDHE shared secret
- [ ] Key schedule: Use "spdm1.3 " (with trailing space) as BinConcat version field
- [ ] Session ID: reqSessionId=0x0001, rspSessionId=0xAEAD, combined=0x0001AEAD
- [ ] Verify full handshake on hardware

### Phase 8: Secured Message Transport (TODO)
- [ ] Implement `wolfTPM2_SPDM_WrapCommand` with real AEAD encryption
- [ ] Implement `wolfTPM2_SPDM_UnwrapResponse` with real AEAD decryption
- [ ] Hook SPDM transport into TPM command send/receive path
- [ ] Sequence number management (per-direction monotonic)
- [ ] Test TPM commands over SPDM secured channel (e.g., SelfTest, GetCapability)

### Phase 9: SPDM-Only Mode (TODO)
- [ ] Test SPDMONLY LOCK vendor command over secured session
- [ ] Test SPDMONLY UNLOCK
- [ ] Verify TPM rejects cleartext commands when locked

### Phase 10: Backend Integration (TODO)
- [ ] Test libspdm backend (`tpm2_spdm_libspdm.c`) with real libspdm library
- [ ] Implement wolfSPDM backend (`tpm2_spdm_wolfspdm.c`) when wolfSPDM is ready
- [ ] Verify backend swapability (compile-time switch)

---

## Key Observations from Hardware Testing

1. **FIPS Indicator**: TPM responds with `00 01` (FIPS approved) in responses, but we send `00 00` (non-FIPS). This works fine.

2. **TPM_RC_DISABLED**: After SPDM communication begins, `TPM2_Startup` returns 0x120 (TPM_RC_DISABLED). The TIS layer and raw SPI I/O still work. SPDM demo tolerates this.

3. **No END_SESSION**: Nuvoton does not support END_SESSION. Sessions persist until TPM reset.

4. **GET_STS_ Response**: Returns 4-byte payload `00 01 00 00`. Byte interpretation TBD - may need Nuvoton documentation for exact field mapping.

5. **GET_PUBK Response**: Returns 120-byte TPMT_PUBLIC. First bytes: `00 23 00 0c 00 05 00 32` which is a valid TPMT_PUBLIC header for ECC P-384.

6. **SPDM Version Negotiation**: GET_VERSION uses v1.0 (0x10) per SPDM spec. TPM responds with supported version v1.3 (0x13). All subsequent messages use v1.3.

---

## Build Configuration

```bash
# Current build (SPDM enabled, no libspdm backend)
./configure --enable-spdm --enable-debug

# Future build with libspdm
./configure --enable-spdm --with-libspdm=/path/to/libspdm --enable-debug

# Future build with wolfSPDM
./configure --enable-spdm --with-wolfspdm=/path/to/wolfspdm --enable-debug
```

## Test Commands

```bash
# Pre-session commands (all working)
sudo ./examples/spdm/spdm_demo --raw-test      # Raw GET_VERSION
sudo ./examples/spdm/spdm_demo --status         # GET_STS_ vendor command
sudo ./examples/spdm/spdm_demo --get-pubkey     # GET_PUBK vendor command
sudo ./examples/spdm/spdm_demo --enable         # NTC2_PreConfig SPDM enable

# Session commands (not yet implemented)
sudo ./examples/spdm/spdm_demo --connect        # Full handshake
sudo ./examples/spdm/spdm_demo --lock           # SPDM-only mode lock
sudo ./examples/spdm/spdm_demo --unlock         # SPDM-only mode unlock
sudo ./examples/spdm/spdm_demo --all            # Full demo sequence
```

---

## Session Flow (Nuvoton NPCT75x)

```
Host (Requester)                    TPM (Responder)
    |                                    |
    |--- GET_VERSION (v1.0) ------------>|
    |<-- VERSION (v1.3) ----------------|
    |                                    |
    |--- VENDOR_DEF(GET_PUBK) --------->|
    |<-- VENDOR_DEF_RSP(TPMT_PUBLIC) ---|
    |                                    |
    |--- KEY_EXCHANGE (ECDHE pubkey) --->|
    |<-- KEY_EXCHANGE_RSP (ECDHE + sig)-|
    |                                    |
    |  [Handshake session keys derived]  |
    |                                    |
    |--- VENDOR_DEF(GIVE_PUB) --------->|  (within handshake session)
    |<-- VENDOR_DEF_RSP ---------------|
    |                                    |
    |--- FINISH (sig + HMAC) ---------->|
    |<-- FINISH_RSP (HMAC) ------------|
    |                                    |
    |  [Application session keys derived]|
    |                                    |
    |--- VENDOR_DEF(TPM2_CMD) --------->|  (AES-256-GCM encrypted)
    |<-- VENDOR_DEF_RSP(TPM2_RSP) -----|  (AES-256-GCM encrypted)
    |                                    |
    |--- VENDOR_DEF(SPDMONLY LOCK) ---->|  (optional)
    |<-- VENDOR_DEF_RSP ---------------|
```
