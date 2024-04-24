/* pkcs7.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    defined(HAVE_PKCS7)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/pkcs7/pkcs7.h>
#include <wolfssl/wolfcrypt/pkcs7.h>

/* Sign PKCS7 using TPM based key:
 * Must Run:
 * 1. `./examples/csr/csr`
 * 2. `./certs/certreq.sh`
 * 3. Results in `./certs/client-rsa-cert.der`
 */

/* The PKCS7 EX functions were added after v3.15.3 */
#include <wolfssl/version.h>
#if defined(LIBWOLFSSL_VERSION_HEX) && \
    LIBWOLFSSL_VERSION_HEX > 0x03015003
    #undef  ENABLE_PKCS7EX_EXAMPLE
    #define ENABLE_PKCS7EX_EXAMPLE
#endif

#ifndef MAX_PKCS7_SIZE
#define MAX_PKCS7_SIZE MAX_CONTEXT_SIZE
#endif

/******************************************************************************/
/* --- BEGIN TPM2 PKCS7 Example -- */
/******************************************************************************/

#ifdef ENABLE_PKCS7EX_EXAMPLE
/* Dummy Function to Get Data */
#define MY_DATA_CHUNKS  WOLFTPM2_MAX_BUFFER
#define MY_DATA_TOTAL  (1024 * 1024) + 12 /* odd remainder for test */
static int GetMyData(byte* buffer, word32 bufSz, word32 offset)
{
    int i;
    const word32 myDataTotal = MY_DATA_TOTAL;

    /* way to return total size */
    if (buffer == NULL)
        return myDataTotal;

    /* check for overflow */
    if (offset >= myDataTotal)
        return 0;

    /* check for remainder */
    if (bufSz > myDataTotal - offset)
        bufSz = myDataTotal - offset;

    /* populate dummy data */
    for (i=0; i<(int)bufSz; i++) {
        buffer[i] = (i & 0xff);
        /* in real case would populate data here */
    }

    return bufSz;
}

/* The wc_PKCS7_EncodeSignedData_ex and wc_PKCS7_VerifySignedData_ex functions
   were added in this PR https://github.com/wolfSSL/wolfssl/pull/1780. */
static int PKCS7_SignVerifyEx(WOLFTPM2_DEV* dev, int tpmDevId, WOLFTPM2_BUFFER* derCert,
    WOLFTPM2_BUFFER* derPubKey, int alg, enum wc_HashType hashType, const char* outFile)
{
    int rc;
    PKCS7 pkcs7;
    wc_HashAlg       hash;
    byte             hashBuf[TPM_MAX_DIGEST_SIZE];
    word32           hashSz;
    byte outputHead[MAX_PKCS7_SIZE], outputFoot[MAX_PKCS7_SIZE];
    int outputHeadSz, outputFootSz;
    byte dataChunk[MY_DATA_CHUNKS];
    word32 dataChunkSz, offset = 0;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE pemFile;
#endif

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    hashSz = wc_HashGetDigestSize(hashType);
    if (hashSz <= 0) {
        return hashSz;
    }

    /* calculate hash for content */
    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        do {
            dataChunkSz = GetMyData(dataChunk, sizeof(dataChunk), offset);
            if (dataChunkSz == 0)
                break;

            rc = wc_HashUpdate(&hash, hashType, dataChunk, dataChunkSz);
            offset += dataChunkSz;
        } while (rc == 0);

        if (rc == 0) {
            rc = wc_HashFinal(&hash, hashType, hashBuf);
        }
        wc_HashFree(&hash, hashType);
    }
    if (rc != 0)
       goto exit;
    dataChunkSz = GetMyData(NULL, 0, 0); /* get total size */

    /* Generate and verify PKCS#7 files containing data using TPM key */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, derCert->buffer, derCert->size);
    if (rc != 0) goto exit;

    pkcs7.content = NULL; /* not used */
    pkcs7.contentSz = dataChunkSz;
    pkcs7.encryptOID = (alg == TPM_ALG_RSA) ? RSAk : ECDSAk;
    pkcs7.hashOID = wc_HashGetOID(hashType);
    pkcs7.rng = wolfTPM2_GetRng(dev);
    /* pass public key instead of private here. The PKCS7 will try a public
     * key decode if using crypto callbacks */
    pkcs7.privateKey = derPubKey->buffer;
    pkcs7.privateKeySz = derPubKey->size;

    outputHeadSz = (int)sizeof(outputHead);
    outputFootSz = (int)sizeof(outputFoot);

    rc = wc_PKCS7_EncodeSignedData_ex(&pkcs7, hashBuf, hashSz,
        outputHead, (word32*)&outputHeadSz,
        outputFoot, (word32*)&outputFootSz);
    if (rc != 0) goto exit;

    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Header %d\n", outputHeadSz);
    TPM2_PrintBin(outputHead, outputHeadSz);

    printf("PKCS7 Footer %d\n", outputFootSz);
    TPM2_PrintBin(outputFoot, outputFootSz);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    pemFile = XFOPEN(outFile, "wb");
    if (pemFile != XBADFILE) {

        /* Header */
        rc = (int)XFWRITE(outputHead, 1, outputHeadSz, pemFile);
        if (rc != outputHeadSz) {
            XFCLOSE(pemFile);
            rc = -1; goto exit;
        }

        /* Body - Data */
        do {
            dataChunkSz = GetMyData(dataChunk, sizeof(dataChunk), offset);
            if (dataChunkSz == 0)
                break;

            rc = (int)XFWRITE(dataChunk, 1, dataChunkSz, pemFile);
            if (rc != (int)dataChunkSz) {
                XFCLOSE(pemFile);
                rc = -1; goto exit;
            }

            offset += dataChunkSz;
        } while (rc == 0);
        dataChunkSz = GetMyData(NULL, 0, 0); /* get total size */

        /* Footer */
        rc = (int)XFWRITE(outputFoot, 1, outputFootSz, pemFile);
        if (rc != outputFootSz) {
            XFCLOSE(pemFile);
            rc = -1; goto exit;
        }

        XFCLOSE(pemFile);
    }
#else
    (void)outFile;
#endif

    /* Test verify with TPM */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;

    pkcs7.contentSz = dataChunkSz;
    rc = wc_PKCS7_VerifySignedData_ex(&pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, outputFootSz);
    if (rc != 0) goto exit;

    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using TPM)\n");

    /* Test verify with software */
    rc = wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;
    pkcs7.contentSz = dataChunkSz;
    rc = wc_PKCS7_VerifySignedData_ex(&pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, outputFootSz);
    if (rc != 0) goto exit;
    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using software)\n");

exit:
    return rc;
}
#endif /* ENABLE_PKCS7EX_EXAMPLE */

static int PKCS7_SignVerify(WOLFTPM2_DEV* dev, int tpmDevId, WOLFTPM2_BUFFER* derCert,
    WOLFTPM2_BUFFER* derPubKey, int alg, enum wc_HashType hashType, const char* outFile)
{
    int rc;
    PKCS7 pkcs7;
    byte  data[] = "My encoded DER cert.";
    byte output[MAX_PKCS7_SIZE];
    int outputSz;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE pemFile;
#endif

    XMEMSET(&pkcs7, 0, sizeof(pkcs7));

    /* Generate and verify PKCS#7 files containing data using TPM key */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, derCert->buffer, derCert->size);
    if (rc != 0) goto exit;

    pkcs7.content = data;
    pkcs7.contentSz = (word32)sizeof(data);
    pkcs7.encryptOID = (alg == TPM_ALG_RSA) ? RSAk : ECDSAk;
    pkcs7.hashOID = wc_HashGetOID(hashType);
    pkcs7.rng = wolfTPM2_GetRng(dev);
    /* pass public key instead of private here. The PKCS7 will try a public
     * key decode if using crypto callbacks */
    pkcs7.privateKey = derPubKey->buffer;
    pkcs7.privateKeySz = derPubKey->size;

    rc = wc_PKCS7_EncodeSignedData(&pkcs7, output, sizeof(output));
    if (rc <= 0) goto exit;
    wc_PKCS7_Free(&pkcs7);
    outputSz = rc;

    printf("PKCS7 Signed Container %d\n", outputSz);
    TPM2_PrintBin(output, outputSz);

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    pemFile = XFOPEN(outFile, "wb");
    if (pemFile != XBADFILE) {
        rc = (int)XFWRITE(output, 1, outputSz, pemFile);
        XFCLOSE(pemFile);
        if (rc != outputSz) {
            rc = -1; goto exit;
        }
    }
#endif

    /* Test verify with TPM */
    rc = wc_PKCS7_Init(&pkcs7, NULL, tpmDevId);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_VerifySignedData(&pkcs7, output, outputSz);
    if (rc != 0) goto exit;
    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using TPM)\n");

    /* Test verify with software */
    rc = wc_PKCS7_Init(&pkcs7, NULL, INVALID_DEVID);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_InitWithCert(&pkcs7, NULL, 0);
    if (rc != 0) goto exit;
    rc = wc_PKCS7_VerifySignedData(&pkcs7, output, outputSz);
    if (rc != 0) goto exit;
    wc_PKCS7_Free(&pkcs7);

    printf("PKCS7 Container Verified (using software)\n");

exit:
    return rc;
}

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/pkcs7/pkcs7 [-ecc/-rsa] [-out=]\n");
    printf("* -ecc/-rsa: Use RSA or ECC key (default is RSA)\n");
    printf("* -incert=file: Certificate for key used\n");
    printf("\tDefault: RSA=./certs/client-rsa-cert.der, ECC=./certs/client-ecc-cert.der\n");
    printf("* -out=file: Generated PKCS7 file containing signed data and certificate\n");
}

int TPM2_PKCS7_Example(void* userCtx)
{
    return TPM2_PKCS7_ExampleArgs(userCtx, 0, NULL);
}
int TPM2_PKCS7_ExampleArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY tpmKey;
    TPMT_PUBLIC publicTemplate;
    TpmCryptoDevCtx tpmCtx;
    int tpmDevId;
    WOLFTPM2_BUFFER derCert;
    WOLFTPM2_BUFFER derPubKey;
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE derFile;
    const char* inCert = NULL;
#endif
    TPM_ALG_ID alg = TPM_ALG_RSA;
    const char* outFile =   "./examples/pkcs7/pkcs7tpmsigned.p7s";
    const char* outFileEx = "./examples/pkcs7/pkcs7tpmsignedex.p7s";
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;

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
    #if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
        else if (XSTRNCMP(argv[argc-1], "-incert=",
                XSTRLEN("-incert=")) == 0) {
            inCert = argv[argc-1] + XSTRLEN("-incert=");
        }
    #endif
        else if (XSTRNCMP(argv[argc-1], "-out=",
                XSTRLEN("-out=")) == 0) {
            outFile = argv[argc-1] + XSTRLEN("-out=");
        }
        else if (XSTRNCMP(argv[argc-1], "-outex=",
                XSTRLEN("-outex=")) == 0) {
            outFileEx = argv[argc-1] + XSTRLEN("-outex=");
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("TPM2 PKCS7 Example\n");


    XMEMSET(&derCert, 0, sizeof(derCert));
    XMEMSET(&derPubKey, 0, sizeof(derPubKey));
    XMEMSET(&tpmKey, 0, sizeof(tpmKey));
    XMEMSET(&storageKey, 0, sizeof(storageKey));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* Setup the wolf crypto device callback */
    XMEMSET(&tpmCtx, 0, sizeof(tpmCtx));
#ifndef NO_RSA
    if (alg == TPM_ALG_RSA)
        tpmCtx.rsaKey = &tpmKey;
#endif
#ifdef HAVE_ECC
    if (alg == TPM_ALG_ECC)
        tpmCtx.eccKey = &tpmKey;
#endif
    rc = wolfTPM2_SetCryptoDevCb(&dev, wolfTPM2_CryptoDevCb, &tpmCtx, &tpmDevId);
    if (rc < 0) goto exit;

    /* get SRK */
    rc = getPrimaryStoragekey(&dev, &storageKey, alg);
    if (rc != 0) goto exit;

    /* Create/Load key for PKCS7 signing */
    if (alg == TPM_ALG_RSA) {
        rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
        if (rc == 0) {
            rc = getRSAkey(&dev,
                        &storageKey,
                        &tpmKey,
                        NULL,
                        tpmDevId,
                        (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                        &publicTemplate);
        }
        if (rc == 0) {
            /* export public key as DER for PKCS7, so it has the key information */

        }
    }
    else {
        TPM_ECC_CURVE curve;
    #if defined(NO_ECC256) && defined(HAVE_ECC384) && ECC_MIN_KEY_SZ <= 384
        /* make sure we use a curve that is enabled */
        curve = TPM_ECC_NIST_P384;
    #else
        curve = TPM_ECC_NIST_P256;
    #endif

        rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
            TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
            TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
            curve, TPM_ALG_ECDSA);
        if (rc == 0) {
            rc = getECCkey(&dev,
                            &storageKey,
                            &tpmKey,
                            NULL,
                            tpmDevId,
                            (byte*)gKeyAuth, sizeof(gKeyAuth)-1,
                            &publicTemplate);
        }
        if (rc == 0) {
            /* export public key as DER for PKCS7, so it has the key information */

        }
    }
    if (rc != 0) goto exit;
    wolfTPM2_SetAuthHandle(&dev, 0, &tpmKey.handle);

    /* load DER certificate for TPM key (obtained by running
     * `./examples/csr/csr` and `./certs/certreq.sh`) */
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    if (inCert == NULL) {
        if (alg == TPM_ALG_RSA)
            inCert = "./certs/client-rsa-cert.der";
        else
            inCert = "./certs/client-ecc-cert.der";
    }
    derFile = XFOPEN(inCert, "rb");
    if (derFile != XBADFILE) {
        XFSEEK(derFile, 0, XSEEK_END);
        derCert.size = (int)XFTELL(derFile);
        XREWIND(derFile);
        if (derCert.size > (int)sizeof(derCert.buffer)) {
            rc = BUFFER_E;
        }
        else {
            rc = (int)XFREAD(derCert.buffer, 1, derCert.size, derFile);
            rc = (rc == derCert.size) ? 0 : -1;
        }
        XFCLOSE(derFile);
        if (rc != 0) goto exit;
    }
#endif

    /* Export TPM public key as DER/ASN.1 (should match certificate) */
    derPubKey.size = (int)sizeof(derPubKey.buffer);
    rc = wolfTPM2_ExportPublicKeyBuffer(&dev, &tpmKey,
        ENCODING_TYPE_ASN1, derPubKey.buffer, (word32*)&derPubKey.size);
    if (rc != 0) goto exit;

    /* PKCS 7 sign/verify example */
    rc = PKCS7_SignVerify(&dev, tpmDevId, &derCert, &derPubKey, alg, hashType,
        outFile);
    if (rc != 0) goto exit;

#ifdef ENABLE_PKCS7EX_EXAMPLE
    /* PKCS 7 large data sign/verify example */
    rc = PKCS7_SignVerifyEx(&dev, tpmDevId, &derCert, &derPubKey, alg, hashType,
        outFileEx);
    if (rc != 0) goto exit;
#endif

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &tpmKey.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END TPM2 PKCS7 Example -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && WOLFTPM_CRYPTOCB && HAVE_PKCS7 */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && defined(WOLFTPM_CRYPTOCB) && \
    defined(HAVE_PKCS7)
    rc = TPM2_PKCS7_ExampleArgs(NULL, argc, argv);
#else
    (void)argc;
    (void)argv;

    printf("Wrapper/PKCS7/CryptoDev code not compiled in\n");
    printf("Build wolfssl with ./configure --enable-pkcs7 --enable-cryptocb\n");
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
