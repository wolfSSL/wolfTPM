/* seal_policy_auth_nv_external.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/* This is a helper tool for setting policies on a TPM 2.0 PCR */

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    defined(WOLFSSL_PUBLIC_MP) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include <examples/nvram/nvram.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>

#define ECC_KEY_SIZE 32

/******************************************************************************/
/* --- BEGIN TPM2.0 PCR Policy example tool  -- */
/******************************************************************************/

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/nvram/seal_policy_auth_nv_external [-aes/xor] [pcr]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* pcr: PCR index between 0-23 (default %d)\n", TPM2_DEMO_PCR_INDEX);
}

static const word32 sealNvIndex = TPM2_DEMO_NV_TEST_INDEX;
static const word32 policyDigestNvIndex = TPM2_DEMO_NV_TEST_INDEX + 1;

/* currently only supports ecc256 */
int TPM2_PCR_Seal_With_Policy_Auth_NV_External_Test(void* userCtx, int argc, char *argv[])
{
    int i;
    int rc = -1;
    WOLFTPM2_NV nv;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storage;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_KEY authKey;
    TPMT_PUBLIC authTemplate;
    /* default to aes since parm encryption is required */
    TPM_ALG_ID paramEncAlg = TPM_ALG_CFB;
    word32 pcrIndex = TPM2_DEMO_PCR_INDEX;
    word32 pcrArray[48];
    word32 pcrArraySz = 0;
    byte secret[16];
    byte secretOut[16];
    word32 secretOutSz = (word32)sizeof(secretOut);
    wc_Sha256 sha;
    byte zeroExpiry[4];
    byte hash[WC_SHA256_DIGEST_SIZE];
    ecc_key external_key;
    WC_RNG rng;
    byte sig[ECC_KEY_SIZE * 2];
    word32 sigSz = ECC_KEY_SIZE * 2;
    byte qx[ECC_KEY_SIZE];
    word32 qxSz = ECC_KEY_SIZE;
    byte qy[ECC_KEY_SIZE];
    word32 qySz = ECC_KEY_SIZE;
    mp_int r, s;

    XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
    XMEMSET(&storage, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(&authKey, 0, sizeof(WOLFTPM2_KEY));
    XMEMSET(&authTemplate, 0, sizeof(TPMT_PUBLIC));
    XMEMSET(zeroExpiry, 0, sizeof(zeroExpiry));

    /* set secret */
    for (i = 0; i < (int)sizeof(secret); i++) {
        secret[i] = i;
    }

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (argv[argc-1][0] != '-') {
            /* TODO: Allow selection of multiple PCR's SHA-1 or SHA2-256 */
            pcrIndex = XATOI(argv[argc-1]);
            if (pcrIndex > PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrArray[pcrArraySz] = pcrIndex;
            pcrArraySz++;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    if (pcrArraySz == 0) {
        pcrArray[pcrArraySz] = TPM2_DEMO_PCR_INDEX;
        pcrArraySz++;
    }

    printf("Example for sealing data to NV memory with policy authorization\n");
    printf("\tPCR Indicies:");

    for (i = 0; i < (int)pcrArraySz; i++) {
        printf("%d ", pcrArray[i]);
    }

    printf("\n");

    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    /* session is required for pcr authorization */
    /* Start an authenticated policy session (salted / unbound) */
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* init rng */
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("wc_InitRng failed\n");
        goto exit;
    }

    /* hash the zero expiry */
    rc = wc_InitSha256(&sha);
    if (rc != 0) {
        printf("wc_InitSha256 failed\n");
        goto exit;
    }

    rc = wc_Sha256Update(&sha, zeroExpiry, sizeof(zeroExpiry));
    if (rc != 0) {
        printf("wc_Sha256Update failed\n");
        goto exit;
    }

    rc = wc_Sha256Final(&sha, hash);
    if (rc != 0) {
        printf("wc_Sha256Final failed\n");
        goto exit;
    }

    /* create an external key */
    rc = wc_ecc_init(&external_key);
    if (rc != 0) {
        printf("wc_ecc_init failed\n");
        goto exit;
    }

    /* make the key */
    rc = wc_ecc_make_key(&rng, ECC_KEY_SIZE, &external_key);
    if (rc != 0) {
        printf("wc_ecc_make_key failed\n");
        goto exit;
    }

    mp_init(&r);
    mp_init(&s);

    rc = wc_ecc_sign_hash_ex(hash, sizeof(hash), &rng, &external_key,
        &r, &s);

    mp_to_unsigned_bin(&r, sig);
    mp_to_unsigned_bin(&s, sig + ECC_KEY_SIZE);

    mp_clear(&r);
    mp_clear(&s);

    if (rc != 0) {
        printf("wc_ecc_sign_hash_ex failed %d\n", rc);
        goto exit;
    }

    sigSz = ECC_KEY_SIZE * 2;

    /* load the public part of the key into the tpm */
    rc = wc_ecc_export_public_raw(&external_key, qx, &qxSz, qy, &qySz);
    if (rc != 0) {
        printf("wc_ecc_export_public_raw failed\n");
        goto exit;
    }

    rc = wolfTPM2_LoadEccPublicKey(&dev, (WOLFTPM2_KEY*)&authKey,
        TPM_ECC_NIST_P256, qx, qxSz, qy, qySz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadEccPublicKey failed\n");
        goto exit;
    }

    /* seal the secret */
    rc = wolfTPM2_SealWithAuthSigNV(&dev, &authKey, &tpmSession, TPM_ALG_SHA256,
        TPM_ALG_SHA256, pcrArray, pcrArraySz, secret, sizeof(secret), NULL, 0,
        sig, sigSz, sealNvIndex, policyDigestNvIndex);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_SealWithAuthPolicyNV failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    /* reset our session */
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    XMEMSET(&tpmSession, 0, sizeof(WOLFTPM2_SESSION));

    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
        TPM_SE_POLICY, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);

    /* set session for authorization of the storage key */
    rc = wolfTPM2_SetAuthSession(&dev, 0, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
        TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    nv.handle.hndl = sealNvIndex;

    /* try to unseal with the regular command, should fail */
    rc = wolfTPM2_NVReadAuth(&dev, &nv, sealNvIndex,
        secretOut, &secretOutSz, 0);
    if (rc == TPM_RC_SUCCESS) {
        printf("wolfTPM2_NVReadAuth failed, it should not have allowed a read"
            " without PolicyAuthorizeNV 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }

    /* unseal the secret */
    rc = wolfTPM2_UnsealWithAuthSigNV(&dev, &authKey,
        &tpmSession, TPM_ALG_SHA256, pcrArray,
        pcrArraySz, NULL, 0, sig, sigSz, sealNvIndex,
        policyDigestNvIndex, secretOut, &secretOutSz);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_UnsealWithAuthSigNV failed 0x%x: %s\n", rc,
            TPM2_GetRCString(rc));
        goto exit;
    }

    if (XMEMCMP(secret, secretOut, sizeof(secret)) != 0) {
        printf("Usealed secret does not match\n");
        goto exit;
    }
    else {
        printf("Usealed secret matches!\n");
    }

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_SetAuthPassword(&dev, 0, NULL);

    wolfTPM2_UnloadHandle(&dev, &authKey.handle);
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 PCR Policy example tool -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT && WOLFSSL_PUBLIC_MP */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    defined(WOLFSSL_PUBLIC_MP) && defined(HAVE_ECC)
    rc = TPM2_PCR_Seal_With_Policy_Auth_NV_External_Test(NULL, argc, argv);
#else
    printf("Wrapper or wolfcrypt or WOLFSSL_PUBLIC_MP code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
