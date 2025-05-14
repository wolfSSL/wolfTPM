/* policy_sign.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Example for signing PCR(s) to create a policy for unsealing a secret
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_FILESYSTEM)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/pcr/pcr.h>

#include <wolfssl/wolfcrypt/hash.h>

/******************************************************************************/
/* --- BEGIN TPM Policy Sign Example -- */
/******************************************************************************/

/* Prefer SHA2-256 for PCR's, and all TPM 2.0 devices support it */
#define USE_PCR_ALG   TPM_ALG_SHA256

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pcr/policy_sign [-pcr=] [-pcrdigest=] [-ecc/-rsa] [-key=pem/der] [-password=] [-out=] [-outpolicy=]\n");
    printf("* -ecc/-rsa: Use RSA or ECC key (default is RSA)\n");
    printf("* -key=keyfile: Private key to sign PCR policy (PEM or DER)\n");
    printf("* -pcr=index: SHA2-256 PCR index < 24 (multiple can be supplied) (default %d)\n", TPM2_DEMO_PCR_INDEX);
    printf("* -pcrdigest=hexstr: PCR Digest (default=Read actual PCR's)\n");
    printf("* -password=password: Optional password for private key\n");
    printf("* -out=file: Signature file (default pcrsig.bin)\n");
    printf("* -outpolicy=file: The authorization policy for this public key (default policyauth.bin)\n");
    printf("Examples:\n");
    printf("./examples/pcr/policy_sign\n");
    printf("./examples/pcr/policy_sign -ecc\n");
    printf("./examples/pcr/policy_sign -rsa -key=./certs/example-rsa2048-key.der -pcr=16 -pcr=15\n");
    printf("./examples/pcr/policy_sign -ecc -key=./certs/example-ecc256-key.der -pcr=16 -pcr=15\n");
    printf("./examples/pcr/policy_sign -pcr=16 -pcr=15 -pcrdigest=ba8ac02be16d9d33080d98611d70bb869aa8ac3fc684ab732b91f75f164b36bc\n");
}

#ifndef WC_MAX_ENCODED_DIG_ASN_SZ
#define WC_MAX_ENCODED_DIG_ASN_SZ 9 /* enum(bit or octet) + length(4) */
#endif

/* Function to sign policy with external key */
static int PolicySign(TPM_ALG_ID alg, const char* keyFile, const char* password,
    TPM_ALG_ID hashAlg, byte* hash, word32 hashSz, byte* sig, word32* sigSz,
    WOLFTPM2_KEY* authPubKey)
{
    int rc = 0;
    int encType = ENCODING_TYPE_ASN1;
    byte* buf = NULL;
    size_t bufSz = 0;
    WC_RNG rng;
    union {
    #ifndef NO_RSA
        RsaKey rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key ecc;
    #endif
    } key;
    const char* keyFileEnd;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&rng, 0, sizeof(rng));

    rc = wc_InitRng(&rng);
    if (rc != 0) {
        printf("wc_InitRng failed\n");
        return rc;
    }

    keyFileEnd = XSTRSTR(keyFile, ".pem");
    if (keyFileEnd != NULL && keyFileEnd[XSTRLEN(".pem")] == '\0') {
        encType = ENCODING_TYPE_PEM;
    }

    printf("Loading %s private key file: %s\n",
        encType == ENCODING_TYPE_PEM ? "PEM" : "DER",
        keyFile);
    rc = loadFile(keyFile, &buf, &bufSz);
    if (rc == 0) {
        /* handle PEM conversion to DER */
        if (encType == ENCODING_TYPE_PEM) {
        #ifdef WOLFTPM2_PEM_DECODE
            /* der size is base 64 decode length */
            word32 derSz = (word32)bufSz * 3 / 4 + 1;
            byte* derBuf = (byte*)XMALLOC(derSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (derBuf == NULL)
                return MEMORY_E;
            rc = wc_KeyPemToDer((byte*)buf, (word32)bufSz, derBuf, derSz, password);
            if (rc >= 0) {
                /* replace buf with DER */
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                bufSz = rc;
                buf = derBuf;
                rc = 0;
            }
        #else
            (void)password;
            rc = NOT_COMPILED_IN;
        #endif
        }
    }
    if (rc == 0 && alg == TPM_ALG_RSA) {
    #if !defined(NO_RSA) && !defined(NO_ASN)
        rc = wc_InitRsaKey(&key.rsa, NULL);
        if (rc == 0) {
            byte encHash[WC_MAX_DIGEST_SIZE + WC_MAX_ENCODED_DIG_ASN_SZ];
            word32 idx = 0;
            rc = wc_RsaPrivateKeyDecode(buf, &idx, &key.rsa, (word32)bufSz);
            if (rc == 0) {
                rc = wolfTPM2_DecodeRsaDer(buf, (word32)bufSz, &authPubKey->pub, NULL, 0);
            }
            if (rc == 0) {
                /* ASN.1 encode hash */
                int oid;
                oid = TPM2_GetHashType(hashAlg);
                oid = wc_HashGetOID((enum wc_HashType)oid);
                rc = wc_EncodeSignature(encHash, hash, hashSz, oid);
                if (rc > 0) {
                    hashSz = rc;
                #ifdef WOLFTPM_DEBUG_VERBOSE
                    printf("Encoded Hash %d\n", hashSz);
                    printHexString(encHash, hashSz, 32);
                #endif
                    rc = 0;
                }
            }
            if (rc == 0) {
                *sigSz = wc_RsaEncryptSize(&key.rsa);
                rc = wc_RsaSSL_Sign(encHash, hashSz, sig, *sigSz, &key.rsa, &rng);
                if (rc >= 0) {
                    *sigSz = rc;
                    rc = 0;
                }
            }
            wc_FreeRsaKey(&key.rsa);
        }
    #else
        (void)hashAlg;
        rc = NOT_COMPILED_IN;
    #endif
    }
    else if (rc == 0 && alg == TPM_ALG_ECC) {
    #if defined(HAVE_ECC) && defined(WOLFSSL_PUBLIC_MP) && !defined(NO_ASN)
        rc = wc_ecc_init(&key.ecc);
        if (rc == 0) {
            word32 idx = 0;
            rc = wc_EccPrivateKeyDecode(buf, &idx, &key.ecc, (word32)bufSz);
            if (rc == 0) {
                rc = wolfTPM2_DecodeEccDer(buf, (word32)bufSz, &authPubKey->pub, NULL, 0);
            }
            if (rc == 0) {
                mp_int r, s;
                rc = mp_init_multi(&r, &s, NULL, NULL, NULL, NULL);
                if (rc == 0) {
                    rc = wc_ecc_sign_hash_ex(hash, hashSz, &rng, &key.ecc, &r, &s);
                }
                if (rc == 0) {
                    word32 keySz = key.ecc.dp->size, rSz, sSz;
                    *sigSz = keySz * 2;
                    XMEMSET(sig, 0, *sigSz);
                    /* export sign r/s - zero pad to key size */
                    rSz = mp_unsigned_bin_size(&r);
                    mp_to_unsigned_bin(&r, &sig[keySz - rSz]);
                    sSz = mp_unsigned_bin_size(&s);
                    mp_to_unsigned_bin(&s, &sig[keySz + (keySz - sSz)]);
                    mp_clear(&r);
                    mp_clear(&s);
                }
            }
            wc_ecc_free(&key.ecc);
        }
    #else
        (void)hashAlg;
        rc = NOT_COMPILED_IN;
    #endif
    }
    else {
        rc = BAD_FUNC_ARG;
    }
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_FreeRng(&rng);

    (void)hash;
    (void)hashSz;
    (void)sig;
    (void)sigSz;
    (void)authPubKey;

    if (rc != 0) {
        printf("Policy Sign with external key failed %d\n", rc);
    }
    return rc;
}

int TPM2_PCR_PolicySign_Example(void* userCtx, int argc, char *argv[])
{
    int i;
    int rc = -1;
    TPM_ALG_ID alg = TPM_ALG_RSA;
    TPM_ALG_ID pcrAlg = USE_PCR_ALG;
    byte pcrArray[PCR_SELECT_MAX*2];
    word32 pcrArraySz = 0;
    const char* keyFile = NULL;
    const char* password = NULL;
    const char* outFile = "pcrsig.bin";
    const char* outPolicyFile = "policyauth.bin";
    byte pcrDigest[WC_MAX_DIGEST_SIZE];
    word32 pcrDigestSz = 0;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = 0;
    byte sig[512]; /* up to 4096-bit key */
    word32 sigSz = 0;
    byte* policyRef = NULL; /* optional nonce */
    word32 policyRefSz = 0;

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-ecc") == 0) {
            alg = TPM_ALG_ECC;
        }
        else if (XSTRCMP(argv[argc-1], "-rsa") == 0) {
            alg = TPM_ALG_RSA;
        }
        else if (XSTRNCMP(argv[argc-1], "-pcr=", XSTRLEN("-pcr=")) == 0) {
            const char* pcrStr = argv[argc-1] + XSTRLEN("-pcr=");
            byte pcrIndex = (byte)XATOI(pcrStr);
            if (pcrIndex > PCR_LAST) {
                printf("PCR index is out of range (0-23)\n");
                usage();
                return 0;
            }
            pcrArray[pcrArraySz] = pcrIndex;
            pcrArraySz++;
        }
        else if (XSTRNCMP(argv[argc-1], "-pcrdigest=", XSTRLEN("-pcrdigest=")) == 0) {
            const char* hashHexStr = argv[argc-1] + XSTRLEN("-pcrdigest=");
            int hashHexStrLen = (int)XSTRLEN(hashHexStr);
            if (hashHexStrLen > (int)sizeof(pcrDigest)*2+1)
                pcrDigestSz = -1;
            else
                pcrDigestSz = hexToByte(hashHexStr, pcrDigest, hashHexStrLen);
            if (pcrDigestSz <= 0) {
                fprintf(stderr, "Invalid PCR hash length\n");
                usage();
                return -1;
            }
        }
        else if (XSTRNCMP(argv[argc-1], "-password=",
                XSTRLEN("-password=")) == 0) {
            password = (const char*)(argv[argc-1] + XSTRLEN("-password="));
        }
        else if (XSTRNCMP(argv[argc-1], "-key=",
                XSTRLEN("-key=")) == 0) {
            keyFile = argv[argc-1] + XSTRLEN("-key=");
        }
        else if (XSTRNCMP(argv[argc-1], "-out=",
                XSTRLEN("-out=")) == 0) {
            outFile = argv[argc-1] + XSTRLEN("-out=");
        }
        else if (XSTRNCMP(argv[argc-1], "-outpolicy=",
                XSTRLEN("-outpolicy=")) == 0) {
            outPolicyFile = argv[argc-1] + XSTRLEN("-outpolicy=");
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("Sign PCR Policy Example\n");

#ifndef HAVE_ECC
    if (alg == TPM_ALG_ECC) {
        printf("ECC not compiled in!\n");
        return 0; /* don't report error */
    }
#endif
#ifdef NO_RSA
    if (alg == TPM_ALG_RSA) {
        printf("RSA not compiled in!\n");
        return 0; /* don't report error */
    }
#endif

    /* Setup PCR's */
    if (pcrArraySz == 0) {
        pcrArray[pcrArraySz] = TPM2_DEMO_PCR_INDEX;
        pcrArraySz++;
    }

    printf("PCR Index(s) (%s): ", TPM2_GetAlgName(pcrAlg));
    for (i = 0; i < (int)pcrArraySz; i++) {
        printf("%d ", pcrArray[i]);
    }
    printf("\n");

    /* Policy Signing Key */
    if (keyFile != NULL)
        printf("Policy Signing Key: %s\n", keyFile);

    /* PCR Hash - Use provided hash or read PCR's and get hash */
    if (pcrDigestSz == 0) {
        WOLFTPM2_DEV dev;
        XMEMSET(&dev, 0, sizeof(WOLFTPM2_DEV));
        rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
        if (rc == 0) {
            rc = wolfTPM2_PCRGetDigest(&dev, pcrAlg, pcrArray, pcrArraySz,
                pcrDigest, &pcrDigestSz);
            wolfTPM2_Cleanup(&dev);
        }
        if (rc != TPM_RC_SUCCESS) {
            printf("Error getting PCR's! 0x%x: %s\n", rc, TPM2_GetRCString(rc));
            goto exit;
        }
    }
    printf("PCR Digest (%d bytes):\n", pcrDigestSz);
    printHexString(pcrDigest, pcrDigestSz, pcrDigestSz);

    /* Build PCR Policy to Sign */
    XMEMSET(digest, 0, sizeof(digest));
    digestSz = TPM2_GetHashDigestSize(pcrAlg);
    rc = wolfTPM2_PolicyPCRMake(pcrAlg, pcrArray, pcrArraySz,
        pcrDigest, pcrDigestSz, digest, &digestSz);
    if (rc != 0) goto exit;
    printf("PCR Policy Digest (%d bytes):\n", digestSz);
    printHexString(digest, digestSz, digestSz);

    /* Add policyRef (if blank just re-hash) */
    rc = wolfTPM2_PolicyRefMake(pcrAlg, digest, &digestSz, policyRef, policyRefSz);
    if (rc != 0) goto exit;
    printf("PCR Policy Digest (w/PolicyRef) (%d bytes):\n", digestSz);
    printHexString(digest, digestSz, digestSz);

    /* Sign the PCR policy (use private key provided or do externally) */
    if (keyFile != NULL) {
        WOLFTPM2_KEY authPubKey;
        XMEMSET(&authPubKey, 0, sizeof(authPubKey));
        rc = PolicySign(alg, keyFile, password, pcrAlg, digest, digestSz,
            sig, &sigSz, &authPubKey);
        if (rc == 0) {
            printf("PCR Policy Signature (%d bytes):\n", sigSz);
            printHexString(sig, sigSz, 32);
            rc = writeBin(outFile, sig, sigSz);
        }
        if (rc == 0) {
            /* Create Signing Authority Policy */
            /* Generate the authorization policy for this public key */

            /* Policy Digest used for creation of a keyed hash */
            XMEMSET(digest, 0, sizeof(digest));
            digestSz = TPM2_GetHashDigestSize(pcrAlg);
            rc = wolfTPM2_PolicyAuthorizeMake(pcrAlg, &authPubKey.pub,
                digest, &digestSz, NULL, 0);
            if (rc == 0) {
                printf("Policy Authorize Digest (%d bytes):\n", digestSz);
                printHexString(digest, digestSz, digestSz);
                rc = writeBin(outPolicyFile, digest, digestSz);
            }
        }
    }
    else {
        /* Print policy hash to sign externally and exit early */
        printf("No private key to sign policy!\n");
        printf("Externally sign the PCR Policy digest\n");
        rc = 0;
        goto exit;
    }

exit:
    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    return rc;
}
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT && !NO_FILESYSTEM */

/******************************************************************************/
/* --- END TPM Secure Boot Sign Policy Example -- */
/******************************************************************************/

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT) && \
    !defined(NO_FILESYSTEM)
    rc = TPM2_PCR_PolicySign_Example(NULL, argc, argv);
#else
    printf("Example not compiled in! Requires Wrapper and wolfCrypt\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* NO_MAIN_DRIVER */
