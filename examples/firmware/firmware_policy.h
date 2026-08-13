/* firmware_policy.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Shared caller-supplied policy authorization helpers for the firmware update
 * examples (ifx_fw_update and st33_fw_update). The vendor difference is carried
 * by the fuStartCC parameter, so there is no per-vendor logic here. */

#ifndef WOLFTPM_EXAMPLE_FIRMWARE_POLICY_H
#define WOLFTPM_EXAMPLE_FIRMWARE_POLICY_H

#include <wolftpm/tpm2_wrap.h>

/* These helpers are built on the wolfTPM2 wrapper API and use wolfCrypt hashing */
#if defined(WOLFTPM_FIRMWARE_UPGRADE) && !defined(WOLFTPM2_NO_WRAPPER) && \
    !defined(WOLFTPM2_NO_WOLFCRYPT)

#ifdef __cplusplus
extern "C" {
#endif

/* Single definition of the "policy helpers are available" condition, so the
 * two firmware examples cannot drift. Tested as WOLFTPM_HAVE_FW_POLICY. */
#define WOLFTPM_HAVE_FW_POLICY

/* Records what firmware_policy_session_setup actually provisioned, so cleanup
 * only touches a policy this example installed and can reproduce the branch
 * digests needed to authorize the rollback. Treat as opaque; zero before
 * use. */
typedef struct FirmwarePolicyCtx {
    TPMI_ALG_HASH hashAlg;    /* policy session / authPolicy hash */
    int    useOr;             /* 1 = platform policy is a PolicyOR */
    int    provisioned;       /* 1 = we installed the platform authPolicy */
    word32 branchSz;          /* size of each branch digest below */
    /* PolicyOR branch A: PolicyCommandCode(fuStartCC) */
    byte   branchFu[TPM_MAX_DIGEST_SIZE];
    /* PolicyOR branch B: PolicyCommandCode(TPM_CC_SetPrimaryPolicy) */
    byte   branchSpp[TPM_MAX_DIGEST_SIZE];
} FirmwarePolicyCtx;

/* Non-destructive self-test: exercises wolfTPM2_PolicyOR at SHA-256/384/512 and
 * checks the TPM's running policy digest against an offline computation. A hash
 * the TPM does not implement is reported and skipped. Returns 0 on overall
 * success (all supported hashes matched), -1 if any supported hash failed. */
int firmware_policy_selftest_all(WOLFTPM2_DEV* dev);

/* Provision the platform authPolicy and return a session that satisfies it, so
 * the firmware-start command can be authorized by a caller-controlled policy
 * instead of the vendor default. When useOr is set the platform policy is a
 * PolicyOR of PolicyCommandCode(fuStartCC) and
 * PolicyCommandCode(TPM_CC_SetPrimaryPolicy); otherwise it is a single
 * PolicyCommandCode(fuStartCC) branch. fuStartCC is the vendor FieldUpgrade
 * start command code. ctx records what was provisioned and must be passed to
 * firmware_policy_clear. On success *session is started and satisfied (the
 * caller passes it to wolfTPM2_FirmwareUpgrade_ex and must UnloadHandle it).
 * On failure any provisioned platform policy is cleared so a later default-auth
 * run is not locked out. */
int firmware_policy_session_setup(WOLFTPM2_DEV* dev, FirmwarePolicyCtx* ctx,
    TPMI_ALG_HASH hashAlg, int useOr, TPM_CC fuStartCC,
    WOLFTPM2_SESSION* session);

/* Clear a platform authPolicy this example provisioned, restoring default auth
 * so a later default-auth run is not locked out. Does nothing (and returns 0)
 * when ctx reports nothing was provisioned, so an unconditional call on an
 * error path cannot wipe a policy the deployment installed itself.
 *
 * Rollback normally uses platform password authorization: per TPM 2.0 Part 1
 * Sec.19.7 a hierarchy is authorized by either its authValue or its authPolicy,
 * so installing an authPolicy does not disable the password path. If the
 * password path fails (a deployment that set a non-default platformAuth) and a
 * PolicyOR was provisioned, the SetPrimaryPolicy branch is used to authorize
 * the clear under policy instead. Returns 0 on success, otherwise the TPM rc;
 * a non-zero return means the platform hierarchy still requires the policy
 * until the TPM is reset or power cycled. */
int firmware_policy_clear(WOLFTPM2_DEV* dev, FirmwarePolicyCtx* ctx);

#ifdef __cplusplus
}
#endif

#endif /* WOLFTPM_FIRMWARE_UPGRADE && !NO_WRAPPER && !NO_WOLFCRYPT */
#endif /* WOLFTPM_EXAMPLE_FIRMWARE_POLICY_H */
