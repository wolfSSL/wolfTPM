/* st33_blob0.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <examples/firmware/st33_blob0.h>

const size_t st33_blob0_sizes[ST33_BLOB0_SIZE_CNT] = {
    ST33_BLOB0_SIZE_NON_LMS_RSA,
    ST33_BLOB0_SIZE_NON_LMS,
    ST33_BLOB0_SIZE_LMS
};

size_t st33_expected_blob0(word32 fwVerMajor, word32 fwVerMinor)
{
    if (fwVerMajor < ST33_BLOB0_GENERATION_LMS_CAPABLE) {
        return ST33_BLOB0_SIZE_NON_LMS_RSA;
    }
    if (fwVerMinor < ST33_BLOB0_VERSION_LMS_REQUIRED) {
        return ST33_BLOB0_SIZE_NON_LMS;
    }
    return ST33_BLOB0_SIZE_LMS;
}

size_t st33_blob0_candidates(word32 fwVerMajor, word32 fwVerMinor,
    int haveCaps, size_t* cand)
{
    size_t idx;
    size_t candCnt = 0;

    if (cand == NULL) {
        return 0;
    }
    if (haveCaps) {
        cand[candCnt++] = st33_expected_blob0(fwVerMajor, fwVerMinor);
    }
    for (idx = 0; idx < ST33_BLOB0_SIZE_CNT; idx++) {
        if (candCnt == 0 || cand[0] != st33_blob0_sizes[idx]) {
            cand[candCnt++] = st33_blob0_sizes[idx];
        }
    }
    return candCnt;
}

size_t st33_detect_blob0(const byte* buf, size_t bufSz, const size_t* cand,
    size_t candCnt)
{
    size_t i, off, len;

    if (buf == NULL || cand == NULL) {
        return 0;
    }
    for (i = 0; i < candCnt; i++) {
        if (bufSz <= cand[i]) {
            continue;
        }
        off = cand[i];
        while (off + 3 <= bufSz) {
            if (buf[off] == 0) {
                break; /* end marker, not a record */
            }
            len = ((size_t)buf[off + 1] << 8) | buf[off + 2];
            /* Reject rather than walk past the end: a payload that does not
             * fit means this candidate is not where blob0 ends. Checked as a
             * subtraction on the remaining bytes so off + 3 + len can never
             * be formed out of range. */
            if (len == 0 || len > bufSz - off - 3) {
                break;
            }
            off += 3 + len;
        }
        if (off == bufSz) {
            return cand[i];
        }
    }
    return 0;
}
