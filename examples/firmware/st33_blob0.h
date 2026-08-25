/* st33_blob0.h
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

/* ST33 firmware image (.fi) layout helpers, split out of st33_fw_update.c so
 * the block-chain parser that decides where the manifest ends can be unit
 * tested. Pure buffer logic - no TPM calls, no wolfCrypt. */

#ifndef WOLFTPM_EXAMPLE_ST33_BLOB0_H
#define WOLFTPM_EXAMPLE_ST33_BLOB0_H

#include <wolftpm/tpm2_types.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The manifest (blob0) is a 33 byte fixed header followed by the firmware
 * digest and the signature over it, so its size follows the algorithms that
 * generation signs with. */
/* gen 1: SHA-256 + RSAPSS-2048 */
#define ST33_BLOB0_SIZE_NON_LMS_RSA 321
/* gen 9 below 512: SHA-384 + ECDSA P-384 */
#define ST33_BLOB0_SIZE_NON_LMS     177
/* gen 9 at 512 and above: embedded LMS signature */
#define ST33_BLOB0_SIZE_LMS         2697

/* LMS is a generation 9 rule. Generation 1 parts are always non-LMS no matter
 * how high the minor version goes (e.g. 1.771). Mirrors
 * ST33_FW_GENERATION_LMS_CAPABLE / ST33_FW_VERSION_LMS_REQUIRED in
 * src/tpm2_wrap.c, which is the authority the library validates against. */
#define ST33_BLOB0_GENERATION_LMS_CAPABLE 9
#define ST33_BLOB0_VERSION_LMS_REQUIRED   512

#define ST33_BLOB0_SIZE_CNT 3
extern const size_t st33_blob0_sizes[ST33_BLOB0_SIZE_CNT];

/* Manifest size the running firmware expects for its next update. Takes the
 * version fields rather than WOLFTPM2_CAPS so it stays free of the wrapper. */
size_t st33_expected_blob0(word32 fwVerMajor, word32 fwVerMinor);

/* Fill cand (at least ST33_BLOB0_SIZE_CNT entries) with every known manifest
 * size. When haveCaps is set the size the firmware version implies is placed
 * first, so it wins if more than one candidate parses. Returns the count. */
size_t st33_blob0_candidates(word32 fwVerMajor, word32 fwVerMinor,
    int haveCaps, size_t* cand);

/* Confirm a candidate blob0 size by walking the block chain that follows it.
 * Every byte after blob0 is a [type:1][len:2 big-endian][payload] record and
 * the chain ends exactly at end of file, so only the correct size lands on
 * the final byte. Candidates are tried in the supplied order. Returns the
 * blob0 size, or 0 when the file does not parse with any candidate. */
size_t st33_detect_blob0(const byte* buf, size_t bufSz, const size_t* cand,
    size_t candCnt);

#ifdef __cplusplus
}
#endif

#endif /* WOLFTPM_EXAMPLE_ST33_BLOB0_H */
