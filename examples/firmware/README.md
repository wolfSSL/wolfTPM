# TPM Firmware Update Support

Currently wolfTPM supports firmware update capability for:
- Infineon SLB9672 (SPI) and SLB9673 (I2C) TPM 2.0 modules. Infineon has open sourced their firmware update.
- STMicroelectronics ST33KTPM TPM 2.0 modules. Support covers generation 1 firmware (RSA signed manifest), generation 9 firmware below 512 (ECDSA signed manifest) and generation 9 firmware at 512 and above (LMS signature requirement).

## Infineon Firmware

### Extracting the firmware

Infineon releases firmware as a .bin file (example: TPM20_15.23.17664.0_R1.BIN).

The .bin contains a 16-byte GUID header, at least one manifest based on key group and the firmware. A typical manifest is 3KB and firmware is 920KB.

We have included a host side tool `ifx_fw_extract` for extracting the manifest and firmware data file required for a TPM upgrade.

Example usage:

```sh
# Build host tool
make

# Help
./ifx_fw_extract --help
Usage:
  ifx_fw_extract <fw-file>
  ifx_fw_extract <fw-file> <keygroup_id> <manifest-file> <data-file>

# Find key groups in .bin
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007

# Extract manifest and firmware data files for key group
./ifx_fw_extract TPM20_26.13.17770.0_R1.BIN 7 TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Reading TPM20_26.13.17770.0_R1.BIN
Found group 00000007
Chosen group found: 00000007
Manifest size is 3224
Data size is 934693
Writing TPM20_26.13.17770.0_R1.MANIFEST
Writing TPM20_26.13.17770.0_R1.DATA
```

### Updating the firmware

The `ifx_fw_update` tool uses the manifest (header) and firmware data file.

The TPM has a vendor capability for getting the key group id. This is populated in the `WOLFTPM2_CAPS.keyGroupId` when `wolfTPM2_GetCapabilities` is called. This value should match the firmware extract tool `keygroup_id`.

```sh
# Help
./ifx_fw_update --help
Infineon Firmware Update Usage:
        ./ifx_fw_update (get info)
        ./ifx_fw_update --abandon (cancel)
        ./ifx_fw_update --policytest (safe policy auth self-test)
        ./ifx_fw_update [policy opts] <manifest_file> <firmware_file>
        ./ifx_fw_update <manifest_file> <firmware_file> (default auth)
Policy options (caller-supplied authorization):
        --policy    provision+satisfy a PolicyCommandCode
        --policyor  provision+satisfy a PolicyOR (multi-branch)
        --sha256|--sha384|--sha512  policy hash (default SHA-256)

# Run without arguments to display the current firmware information including key group id and operational mode
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)

# Run with manifest and firmware files
./ifx_fw_update TPM20_26.13.17770.0_R1.MANIFEST TPM20_26.13.17770.0_R1.DATA
Infineon Firmware Update Tool
	Manifest File: TPM20_26.13.17770.0_R1.MANIFEST
	Firmware File: TPM20_26.13.17770.0_R1.DATA
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1254 (255 same)
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
TPM2_FlushContext: Closed handle 0x3000000
TPM2_StartAuthSession: handle 0x3000000, algorithm NULL
Firmware manifest chunk 1024 offset (0 / 3224), state 1
Firmware manifest chunk 1024 offset (1024 / 3224), state 2
Firmware manifest chunk 1024 offset (2048 / 3224), state 2
Firmware manifest chunk 152 offset (3072 / 3224), state 0
Firmware data chunk offset 0
Firmware data chunk offset 1024
Firmware data chunk offset 2048
Firmware data chunk offset 3072
...
Firmware data chunk offset 932864
Firmware data chunk offset 933888
Firmware data done
Mfg IFX (1), Vendor , Fw 0.0 (0x0)
Operational mode: After finalize or abandon, reboot required (0x4)
KeyGroupId 0x7, FwCounter 1253 (254 same)
TPM2_Shutdown failed 304: Unknown

# Reset or power cycle TPM
./ifx_fw_update
Infineon Firmware Update Tool
TPM2: Caps 0x1ae00082, Did 0x001c, Vid 0x15d1, Rid 0x16
TPM2_Startup pass
Mfg IFX (1), Vendor SLB9673, Fw 26.13 (0x456a)
Operational mode: Normal TPM operational mode (0x0)
KeyGroupId 0x7, FwCounter 1253 (254 same)
```

## ST33 Firmware Update

### Firmware Format Auto-Detection

ST33KTPM firmware update automatically detects the required format based on TPM firmware version:

The manifest (blob0) is a 33 byte fixed header followed by the firmware digest and the signature over it, so its size follows the algorithms that generation signs with:

- **Generation 1 (major version 1, e.g., 1.257 or 1.771)**: Non-LMS format
  - Manifest size: 321 bytes (SHA-256 digest, RSAPSS-2048 signature)
  - Always non-LMS, no matter how high the minor version goes

- **Generation 9 below 512 (e.g., 9.257)**: Non-LMS format
  - Manifest size: 177 bytes (SHA-384 digest, ECDSA P-384 signature)

- **Generation 9 at 512 and above (e.g., 9.512)**: LMS format
  - Manifest size: 2697 bytes (includes embedded LMS signature)

The LMS requirement is a generation 9 rule, so both `fwVerMajor` and `fwVerMinor` from TPM capabilities are consulted. The example confirms its choice against the file itself: everything after blob0 is a chain of `[type][length]` records that ends exactly at end of file, and only the correct manifest size lands on the final byte. No manual format selection is needed.

### Updating the firmware

The `st33_fw_update` tool automatically detects the firmware format.

```sh
# Help
./st33_fw_update --help
ST33 Firmware Update Usage:
	./st33_fw_update (get info)
	./st33_fw_update --abandon (cancel)
	./st33_fw_update --policytest (safe policy auth self-test)
	./st33_fw_update [policy opts] <firmware.fi>
	./st33_fw_update <firmware.fi> (default password auth)
Policy options (caller-supplied authorization):
	--policy    provision+satisfy a PolicyCommandCode
	--policyor  provision+satisfy a PolicyOR (multi-branch)
	--sha256|--sha384|--sha512  policy hash (default SHA-256)

Firmware format is auto-detected from TPM firmware version and the file:
      - Generation 1 (e.g. 1.771): Non-LMS format (321 byte manifest)
      - Generation 9 below 512: Non-LMS format (177 byte manifest)
      - Generation 9 at 512 and above: LMS format (2697 byte manifest)

# Run without arguments to display the current firmware information
./st33_fw_update
ST33 Firmware Update Tool
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.257 (0x0)
Firmware version details: Major=9, Minor=257, Vendor=0x0
Hardware: ST33K (generation 9 firmware below 512)
Firmware update: Non-LMS format required (177 byte manifest)

# Run with firmware file (format auto-detected from TPM version)
./st33_fw_update TPM_ST33KTPM2X_00090200_V1.fi
ST33 Firmware Update Tool
	Firmware File: TPM_ST33KTPM2X_00090200_V1.fi
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.257 (0x0)
Firmware version details: Major=9, Minor=257, Vendor=0x0
Hardware: ST33K (generation 9 firmware below 512)
Firmware update: Non-LMS format required (177 byte manifest)
	Format: Non-LMS (blob0 177 bytes, verified against the block chain)
Firmware Update:
	Total file size: 364290 bytes
	Manifest (blob0): 177 bytes
	Firmware data: 364113 bytes
...
Firmware update completed successfully.
Please reset or power cycle the TPM.

# Example with LMS firmware (generation 9 TPM, firmware at 512 and above)
./st33_fw_update ST33KTPM2X_FAC_00090200_V2.fi
ST33 Firmware Update Tool
	Firmware File: ST33KTPM2X_FAC_00090200_V2.fi
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 3
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.512 (0x0)
Firmware version details: Major=9, Minor=512, Vendor=0x0
Hardware: ST33K (generation 9 firmware at 512 and above)
Firmware update: LMS format required (2697 byte manifest)
	Format: LMS (blob0 2697 bytes, verified against the block chain)
Firmware Update:
	Total file size: 360092 bytes
	Manifest (blob0): 2697 bytes
	Firmware data: 357395 bytes
...
Firmware update completed successfully.
Please reset or power cycle the TPM.

# Cancel an ongoing firmware update
./st33_fw_update --abandon
ST33 Firmware Update Tool
TPM2: Caps 0x30000415, Did 0x0003, Vid 0x104a, Rid 0x 1
TPM2_Startup pass
Mfg STM (2), Vendor ST33KTPM2X, Fw 9.257 (0x0)
Firmware version details: Major=9, Minor=257, Vendor=0x0
Hardware: ST33K (generation 9 firmware below 512)
Firmware update: Non-LMS format required (177 byte manifest)
Firmware Update Abandon:
Success: Please reset or power cycle TPM
```

**Note**: Firmware files cannot be made public and must be obtained separately from STMicroelectronics.

## Policy-Based Authorization (Advanced)

By default wolfTPM manages the platform-hierarchy authorization for the firmware-update *start* command internally: on Infineon it installs and satisfies a `PolicyCommandCode(TPM_CC_FieldUpgradeStartVendor)` policy on the platform primary policy, and on ST33 it uses password authorization (`TPM_RS_PW`) with an empty platform password. This assumes the platform hierarchy has default/empty authorization.

Deployments that gate firmware upgrade behind their own platform policy (for example a signed-policy check, a PCR state, or a multi-branch `PolicyOR`) can supply an already-satisfied authorization session using `wolfTPM2_FirmwareUpgradeHash_ex()`. When a session is supplied:

- **Infineon**: the library does **not** overwrite your platform primary policy. You provision the platform `authPolicy` yourself (via `TPM2_SetPrimaryPolicy` with `authHandle = TPM_RH_PLATFORM`, using SHA2-256 or SHA2-512) and pass a session that satisfies it. Note this applies to the *library*: the `--policy`/`--policyor` example modes are themselves such a caller, and their helper (`examples/firmware/firmware_policy.c`) does overwrite the platform `authPolicy` with a digest it generates. Do not run those modes on a system whose platform hierarchy already carries a policy you need.
- **ST33**: the supplied session replaces the default `TPM_RS_PW` password authorization.

**Supported session contract**: the vendor `FieldUpgradeStart` command is sent with an authorization area carrying only the session handle - empty `nonceCaller`, zero session attributes and an empty HMAC. The supplied session must therefore be an unsalted, unbound `TPM_SE_POLICY` session with no auth value and no parameter encryption. Policies satisfied with `wolfTPM2_PolicyAuthValue()` or `wolfTPM2_PolicyPassword()` are **not** supported, because the session HMAC they require is not serialized on this path; such a session is rejected with `BAD_FUNC_ARG` before anything is sent to the TPM. `PolicyPCR`, `PolicySigned`, `PolicySecret`, `PolicyAuthorize`, `PolicyCommandCode` and `PolicyOR` branches are all fine.

Both SHA2-256 (non-PQC) and SHA2-512 (PQC) policy digests are supported, because the session hash is chosen with `wolfTPM2_StartSession_ex(..., authHash)` and `wolfTPM2_PolicyOR()` carries per-branch digest sizes.

Example: satisfy a multi-branch `PolicyOR` (up to 8 branches, SHA2-512 shown) and start the upgrade under it:

```c
WOLFTPM2_SESSION session;
TPML_DIGEST orList;
uint8_t manifest_hash[TPM_SHA512_DIGEST_SIZE];
int rc;

/* zero both structs - orList must not carry uninitialized branch sizes */
XMEMSET(&session, 0, sizeof(session));
XMEMSET(&orList, 0, sizeof(orList));

/* start a policy session using the desired policy hash (SHA2-512 for PQC) */
rc = wolfTPM2_StartSession_ex(&dev, &session, NULL, NULL,
    TPM_SE_POLICY, TPM_ALG_NULL, TPM_ALG_SHA512);
if (rc != TPM_RC_SUCCESS) goto cleanup;

/* Satisfy one branch (PCR, PolicySigned, PolicyAuthorize, PolicyCommandCode,
 * ...), then OR against the full branch list the platform authPolicy encodes.
 * Set count and each digests[i].size/buffer for every branch you populate.
 * PolicyOR requires at least 2 branches. */
orList.count = 2;
/* orList.digests[0].size = ...; XMEMCPY(orList.digests[0].buffer, ...); */
/* orList.digests[1].size = ...; XMEMCPY(orList.digests[1].buffer, ...); */
rc = wolfTPM2_PolicyOR(&dev, &session, &orList);
if (rc != TPM_RC_SUCCESS) goto cleanup;

/* hash the manifest with the matching algorithm, then start the upgrade under
 * the caller-satisfied session (NULL would use the library-default auth) */
rc = wc_Sha512Hash(manifest, manifest_sz, manifest_hash);
if (rc != 0) goto cleanup;
rc = wolfTPM2_FirmwareUpgradeHash_ex(&dev, TPM_ALG_SHA512,
    manifest_hash, (uint32_t)sizeof(manifest_hash),
    manifest, manifest_sz, fwDataCb, fwCbCtx, &session);

cleanup:
/* On a successful FieldUpgradeStart the TPM consumes the session and the
 * library sets session.handle.hndl to TPM_RH_NULL (0x40000007) - it is NOT
 * zeroed, so do not test for == 0 to detect consumption. Calling
 * wolfTPM2_UnloadHandle is always safe: it is a no-op on TPM_RH_NULL, so this
 * only releases a session that is still loaded. */
if (session.handle.hndl != 0)
    wolfTPM2_UnloadHandle(&dev, &session.handle);
```

Passing `NULL` for the final `startSession` argument makes `wolfTPM2_FirmwareUpgradeHash_ex()` behave exactly like `wolfTPM2_FirmwareUpgradeHash()` (library-managed authorization), so existing code is unaffected.

### Destructive: provisioning replaces any existing platform policy

`--policy`/`--policyor` call `TPM2_SetPrimaryPolicy` on the platform hierarchy with a digest the example generates. TPM 2.0 provides **no way to read a hierarchy's `authPolicy` back** - there is no read command, and `TPMA_PERMANENT` reports only `authValue` state - so the example cannot detect an existing policy, cannot preserve it, and cannot restore it. Cleanup **removes** the policy rather than restoring whatever was there before.

If your platform hierarchy is gated by a policy you need to keep, do not run these modes. The example prints this warning at provisioning time. `--policytest` is unaffected: it is non-destructive and never calls `TPM2_SetPrimaryPolicy`.

The modes also require the normal operational mode. In recovery and finalize modes the library skips `FieldUpgradeStart` entirely, so a caller-supplied session would never be used; the example refuses rather than installing a policy nothing will exercise. On ST33, if the TPM is already in firmware-upgrade mode the policy flags are likewise rejected, since the start command has already run.

### Rollback of the example-provisioned policy

The example `--policy`/`--policyor` modes provision the platform hierarchy `authPolicy` via `TPM2_SetPrimaryPolicy` before the upgrade. On failure the example clears it again so a later default-auth run is not locked out; on success the required TPM reset clears it.

- Rollback normally uses platform **password** authorization. Per TPM 2.0 Part 1 Sec.19.7 a hierarchy is authorized by *either* its `authValue` *or* its `authPolicy`, so installing an `authPolicy` does not disable the password path. With the default empty `platformAuth` the clear always succeeds.
- `--policyor` additionally provisions a `PolicyCommandCode(TPM_CC_SetPrimaryPolicy)` branch alongside the firmware-start branch, so the policy can authorize its own removal. If the password path fails (a deployment that set a non-default `platformAuth`), the example retries the clear under that branch.
- `--policy` provisions a single `PolicyCommandCode(FieldUpgradeStart)` branch and therefore has no policy-based rollback path. It relies entirely on `platformAuth` still being usable.
- Rollback is attempted only when the example actually installed the policy, so an early failure (a missing firmware file, for example) never clears a policy the deployment provisioned itself.
- A failed rollback is reported explicitly and becomes the exit status. If a run is interrupted before cleanup, or the clear fails, the platform hierarchy still requires the policy until the TPM is reset/power-cycled.
