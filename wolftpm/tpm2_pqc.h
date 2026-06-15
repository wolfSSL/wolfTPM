/* tpm2_pqc.h
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

/* Resolves the TPM 2.0 v1.85 / post-quantum feature macros into a single,
 * consistent set used by every translation unit. Entry points (set by the
 * user or by configure) are the umbrella WOLFTPM_V185 / WOLFTPM_PQC and the
 * WOLFTPM_NO_* opt-outs; the positive per-algorithm and per-operation macros
 * below are derived here so the rest of the tree only tests the resolved set.
 *
 *   WOLFTPM_V185      full v1.85 spec. Guards the non-PQC spec additions
 *                     (firmware/SVN properties, alg-name/id mappings, debug
 *                     print) and additively defines WOLFTPM_PQC.
 *    WOLFTPM_PQC      ML-DSA / ML-KEM only (lean entry point; excludes the
 *                     non-PQC v1.85 code guarded by WOLFTPM_V185).
 *     WOLFTPM_MLDSA   WOLFTPM_MLDSA_SIGN / _VERIFY / WOLFTPM_HASH_MLDSA
 *     WOLFTPM_MLKEM   WOLFTPM_MLKEM_ENCAP / _DECAP
 *
 * Everything is on by default once its parent is enabled; opt out with the
 * matching WOLFTPM_NO_* macro. Existing --enable-v185 builds are unchanged.
 */

#ifndef __TPM2_PQC_H__
#define __TPM2_PQC_H__

/* Tier 1: the full v1.85 umbrella additively enables the PQC subset. The
 * non-PQC v1.85 spec code stays guarded by WOLFTPM_V185 directly, so a lean
 * WOLFTPM_PQC build (without WOLFTPM_V185) leaves it out. */
#ifdef WOLFTPM_V185
    #if !defined(WOLFTPM_NO_PQC) && !defined(WOLFTPM_PQC)
        #define WOLFTPM_PQC
    #endif
#endif

/* Tier 2: PQC algorithm families. */
#ifdef WOLFTPM_PQC
    #if !defined(WOLFTPM_NO_MLDSA) && !defined(WOLFTPM_MLDSA)
        #define WOLFTPM_MLDSA
    #endif
    #if !defined(WOLFTPM_NO_MLKEM) && !defined(WOLFTPM_MLKEM)
        #define WOLFTPM_MLKEM
    #endif
#endif

/* Tier 3: per-operation gates under each family. */
#ifdef WOLFTPM_MLDSA
    #if !defined(WOLFTPM_NO_MLDSA_SIGN) && !defined(WOLFTPM_MLDSA_SIGN)
        #define WOLFTPM_MLDSA_SIGN
    #endif
    #if !defined(WOLFTPM_NO_MLDSA_VERIFY) && !defined(WOLFTPM_MLDSA_VERIFY)
        #define WOLFTPM_MLDSA_VERIFY
    #endif
    #if !defined(WOLFTPM_NO_HASH_MLDSA) && !defined(WOLFTPM_HASH_MLDSA)
        #define WOLFTPM_HASH_MLDSA
    #endif
#endif
#ifdef WOLFTPM_MLKEM
    #if !defined(WOLFTPM_NO_MLKEM_ENCAP) && !defined(WOLFTPM_MLKEM_ENCAP)
        #define WOLFTPM_MLKEM_ENCAP
    #endif
    #if !defined(WOLFTPM_NO_MLKEM_DECAP) && !defined(WOLFTPM_MLKEM_DECAP)
        #define WOLFTPM_MLKEM_DECAP
    #endif
#endif

/* Consistency fold-ups: drop a feature whose prerequisites are all disabled. */
#if defined(WOLFTPM_HASH_MLDSA) && !defined(WOLFTPM_MLDSA_SIGN) && \
    !defined(WOLFTPM_MLDSA_VERIFY)
    #undef WOLFTPM_HASH_MLDSA
#endif
#if defined(WOLFTPM_MLDSA) && !defined(WOLFTPM_MLDSA_SIGN) && \
    !defined(WOLFTPM_MLDSA_VERIFY)
    #undef WOLFTPM_MLDSA
#endif
#if defined(WOLFTPM_MLKEM) && !defined(WOLFTPM_MLKEM_ENCAP) && \
    !defined(WOLFTPM_MLKEM_DECAP)
    #undef WOLFTPM_MLKEM
#endif
#if defined(WOLFTPM_PQC) && !defined(WOLFTPM_MLDSA) && !defined(WOLFTPM_MLKEM)
    #undef WOLFTPM_PQC
#endif

#endif /* __TPM2_PQC_H__ */
