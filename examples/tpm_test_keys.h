/* tpm_test_keys.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfTPM.
 *
 * wolfTPM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfTPM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _TPM_TEST_KEYS_H_
#define _TPM_TEST_KEYS_H_

#if !defined(WOLFTPM2_NO_WRAPPER)
#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

WOLFTPM_LOCAL int getPrimaryStoragekey(WOLFTPM2_DEV* pDev,
                                       WOLFTPM2_KEY* pStorageKey,
                                       TPM_ALG_ID alg);

#ifndef NO_RSA
#ifdef WOLFTPM2_NO_WOLFCRYPT
WOLFTPM_LOCAL int getRSAkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            const byte* auth, int authSz);
#else
WOLFTPM_LOCAL int getRSAkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            RsaKey* pWolfRsaKey,
                            int tpmDevId,
                            const byte* auth, int authSz);
#endif /* WOLFTPM2_NO_WOLFCRYPT */
#endif

#ifdef HAVE_ECC
#ifdef WOLFTPM2_NO_WOLFCRYPT
WOLFTPM_LOCAL int getECCkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            const byte* auth, int authSz);
#else
WOLFTPM_LOCAL int getECCkey(WOLFTPM2_DEV* pDev,
                            WOLFTPM2_KEY* pStorageKey,
                            WOLFTPM2_KEY* key,
                            ecc_key* pWolfEccKey,
                            int tpmDevId,
                            const byte* auth, int authSz);
#endif
#endif

#endif /* !WOLFTPM2_NO_WRAPPER */
#endif /* _TPM_TEST_KEYS_H_ */
