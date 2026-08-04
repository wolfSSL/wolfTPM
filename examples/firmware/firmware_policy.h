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

/* Non-destructive self-test: exercises wolfTPM2_PolicyOR at SHA-256/384/512 and
 * checks the TPM's running policy digest against an offline computation. A hash
 * the TPM does not implement is reported and skipped. Returns 0 on overall
 * success (all supported hashes matched), -1 if any supported hash failed. */
int firmware_policy_selftest_all(WOLFTPM2_DEV* dev);

/* Provision the platform authPolicy and return a session that satisfies it, so
 * the firmware-start command can be authorized by a caller-controlled policy
 * instead of the vendor default. When useOr is set the platform policy is a
 * PolicyOR of two branches; otherwise a single PolicyCommandCode branch.
 * fuStartCC is the vendor FieldUpgrade start command code. On success *session
 * is started and satisfied (the caller passes it to wolfTPM2_FirmwareUpgrade_ex
 * and must UnloadHandle it). On failure any provisioned platform policy is
 * cleared so a later default-auth run is not locked out. */
int firmware_policy_session_setup(WOLFTPM2_DEV* dev,
    TPMI_ALG_HASH hashAlg, int useOr, TPM_CC fuStartCC,
    WOLFTPM2_SESSION* session);

/* Clear the platform authPolicy (restore default auth) so a later default-auth
 * run is not locked out. Call after a failed policy-mode upgrade. */
void firmware_policy_clear(WOLFTPM2_DEV* dev);

#ifdef __cplusplus
}
#endif

#endif /* WOLFTPM_FIRMWARE_UPGRADE && !NO_WRAPPER && !NO_WOLFCRYPT */
#endif /* WOLFTPM_EXAMPLE_FIRMWARE_POLICY_H */
