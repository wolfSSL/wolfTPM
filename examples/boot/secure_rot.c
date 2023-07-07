/* secure_rot.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/* Example for using TPM for secure boot root of trust
 */


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/boot/boot.h>

#include <wolfssl/wolfcrypt/hash.h>

/* WC_HASH_TYPE_SHA256 or WC_HASH_TYPE_SHA384 */
#define TPM2_SECURE_ROT_HASH_ALGO  WC_HASH_TYPE_SHA256

#define TPM2_SECURE_ROT_EXAMPLE_PUB_KEY "certs/example-rsa-key-pub.der"

/******************************************************************************/
/* --- BEGIN TPM NVRAM Secure Boot Root of Trust Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/boot/secure_rot [-nvindex] [-write] [-lock]\n");
    printf("* -nvindex=[handle] (default 0x%x)\n",
        TPM2_DEMO_NV_SECURE_ROT_INDEX);
    printf("* -write=filename: DER formatted public key to write\n");
    printf("\tDefault public key: " TPM2_SECURE_ROT_EXAMPLE_PUB_KEY "\n");
    printf("* -lock: Lock the write\n");
}

/* forward declaration */
static int load_file(const char* fname, byte** buf, size_t* bufLen);

/* Example for reading unique system registers for derived authentication
 * used to access TPM NV */
static int GetSystemUniqueAuth(enum wc_HashType hashType, byte* authBuf)
{
    int rc;
    wc_HashAlg hash;
    uint32_t reg1 = 0x01234567;
    uint32_t reg2 = 0x89ABCDEF;
    uint32_t reg3 = 0x01234567;
    uint32_t reg4 = 0x89ABCDEF;

    rc = wc_HashInit(&hash, hashType);
    if (rc == 0) {
        rc = wc_HashUpdate(&hash, hashType, (byte*)&reg1, sizeof(reg1));
        if (rc == 0)
            rc = wc_HashUpdate(&hash, hashType, (byte*)&reg2, sizeof(reg2));
        if (rc == 0)
            rc = wc_HashUpdate(&hash, hashType, (byte*)&reg3, sizeof(reg3));
        if (rc == 0)
            rc = wc_HashUpdate(&hash, hashType, (byte*)&reg4, sizeof(reg4));
        if (rc == 0) {
            rc = wc_HashFinal(&hash, hashType, authBuf);
        }
        wc_HashFree(&hash, hashType);
    }
    return rc;
}

int TPM2_Boot_SecureROT_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    word32 nvAttributes;
    int paramEncAlg = TPM_ALG_CFB; /* always use AES CFB parameter encryption */
    TPMI_RH_NV_AUTH authHandle = TPM_RH_PLATFORM; /* use platform handle to prevent TPM2_Clear from removing */
    const char* filename = TPM2_SECURE_ROT_EXAMPLE_PUB_KEY;
    word32 nvIndex = TPM2_DEMO_NV_SECURE_ROT_INDEX;
    int doWrite = 0, doLock = 0;
    byte* buf = NULL;
    size_t bufSz = 0;
    enum wc_HashType hashType = TPM2_SECURE_ROT_HASH_ALGO;
    byte digest[WC_MAX_DIGEST_SIZE];
    word32 digestSz = wc_HashGetDigestSize(hashType);
    byte authBuf[WC_SHA256_DIGEST_SIZE];

    if (digestSz <= 0) {
        printf("Unsupported hash type %d!\n", hashType);
        usage();
        return -1;
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
        if (XSTRNCMP(argv[argc-1], "-nvindex=", XSTRLEN("-nvindex=")) == 0) {
            nvIndex = (word32)XSTRTOL(argv[argc-1] +
                XSTRLEN("-nvindex="), NULL, 0);
            if ((authHandle == TPM_RH_PLATFORM && (
                    nvIndex > TPM_20_PLATFORM_MFG_NV_SPACE &&
                    nvIndex < TPM_20_OWNER_NV_SPACE)) ||
                (authHandle == TPM_RH_OWNER && (
                    nvIndex > TPM_20_OWNER_NV_SPACE &&
                    nvIndex < TPM_20_TCG_NV_SPACE)))
            {
                printf("Invalid NV Index %s\n", argv[argc-1] + 8);
                nvIndex = 0;
            }
        }
        else if (XSTRNCMP(argv[argc-1], "-write=", XSTRLEN("-write=")) == 0) {
            doWrite = 1;
            filename = argv[argc-1] + XSTRLEN("-write=");
        }
        else if (XSTRCMP(argv[argc-1], "-write") == 0) {
            doWrite = 1;
        }
        else if (XSTRCMP(argv[argc-1], "-lock") == 0) {
            doLock = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(digest, 0, sizeof(digest));

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* Derive a unique value from hardware to authenticate the NV */
    rc = GetSystemUniqueAuth(hashType, authBuf);
    if (rc != 0) {
        printf("Error getting system unique NV auth! %d\n", rc);
        goto exit;
    }
    printf("NV Auth (%d)\n", (int)sizeof(authBuf));
    TPM2_PrintBin(authBuf, sizeof(authBuf));

    /* Start TPM session for parameter encryption */
    printf("Parameter Encryption: Enabled. (AES CFB)\n\n");
    rc = wolfTPM2_StartSession(&dev, &tpmSession, NULL, NULL,
            TPM_SE_HMAC, paramEncAlg);
    if (rc != 0) goto exit;
    printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
        (word32)tpmSession.handle.hndl);
    /* Set TPM session attributes for parameter encryption */
    rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
        (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt |
         TPMA_SESSION_continueSession));
    if (rc != 0) goto exit;

    /* Open file */
    if (doWrite) {
        printf("Storing hash of public key file %s to "
            "NV index 0x%x with password protection\n\n",
            filename, nvIndex);

        rc = load_file(filename, &buf, &bufSz);
        if (rc == 0) {
            /* hash public key */
            rc = wc_Hash(hashType, buf, (word32)bufSz, digest, digestSz);

            printf("Public Key Hash (%d)\n", digestSz);
            TPM2_PrintBin(digest, digestSz);
        }
        if (rc == 0) {
            /* Get NV attributes */
            parent.hndl = authHandle;
            rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
        }
        if (rc == 0) {
            /* allow this NV to be locked */
            nvAttributes |= TPMA_NV_WRITEDEFINE;

            /* Create NV */
            rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
                nvAttributes, digestSz, authBuf, sizeof(authBuf));
            if (rc == TPM_RC_NV_DEFINED) {
                printf("Warning: NV Index 0x%x already exists!\n", nvIndex);
                rc = 0;
            }
        }
        if (rc == 0) {
            /* Write digest to NV */
            rc = wolfTPM2_NVWriteAuth(&dev, &nv, nvIndex, digest, digestSz, 0);
        }
        if (rc != 0) goto exit;
        printf("Wrote %d bytes to NV 0x%x\n", digestSz, nvIndex);
    }

    /* Setup the NV access */
    XMEMSET(&nv, 0, sizeof(nv));
    nv.handle.hndl = nvIndex;
    nv.handle.auth.size = sizeof(authBuf);
    XMEMCPY(nv.handle.auth.buffer, authBuf, sizeof(authBuf));

    /* Read access */
    printf("Reading NV 0x%x public key hash\n", nvIndex);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, digest, &digestSz, 0);
    if (rc == 0) {
        printf("Read Public Key Hash (%d)\n", digestSz);
        TPM2_PrintBin(digest, digestSz);
    }
    else if ((rc & RC_MAX_FMT1) == TPM_RC_HANDLE) {
        printf("NV index does not exist\n");
    }

    /* Locking */
    if (doLock) {
        printf("Locking NV index 0x%x\n", nvIndex);
        rc = wolfTPM2_NVWriteLock(&dev, &nv);
        if (rc != 0) goto exit;
        printf("NV 0x%x locked\n", nvIndex);
    }

exit:

    if (rc != 0) {
        printf("\nFailure 0x%x: %s\n\n", rc, wolfTPM2_GetRCString(rc));
    }
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);
    wolfTPM2_Cleanup(&dev);

    return rc;
}

static int load_file(const char* fname, byte** buf, size_t* bufLen)
{
    int ret;
#if !defined(NO_FILESYSTEM)
    long int fileSz;
    XFILE lFile;

    if (fname == NULL || buf == NULL || bufLen == NULL)
        return BAD_FUNC_ARG;

    /* set defaults */
    *buf = NULL;
    *bufLen = 0;

    /* open file (read-only binary) */
    lFile = XFOPEN(fname, "rb");
    if (!lFile) {
        fprintf(stderr, "Error loading %s\n", fname);
        return BUFFER_E;
    }

    XFSEEK(lFile, 0, XSEEK_END);
    fileSz = (int)ftell(lFile);
    XFSEEK(lFile, 0, XSEEK_SET);
    if (fileSz  > 0) {
        *bufLen = (size_t)fileSz;
        *buf = (byte*)XMALLOC(*bufLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*buf == NULL) {
            ret = MEMORY_E;
            fprintf(stderr,
                    "Error allocating %lu bytes\n", (unsigned long)*bufLen);
        }
        else {
            size_t readLen = fread(*buf, *bufLen, 1, lFile);

            /* check response code */
            ret = (readLen > 0) ? 0 : -1;
        }
    }
    else {
        ret = BUFFER_E;
    }
    fclose(lFile);
#else
    (void)fname;
    (void)buf;
    (void)bufLen;
    ret = NOT_COMPILED_IN;
#endif
    return ret;
}
/* !NO_FILESYSTEM */

/******************************************************************************/
/* --- END TPM NVRAM Secure Boot Root of Trust Example -- */
/******************************************************************************/
#endif /* !WOLFTPM2_NO_WRAPPER && !WOLFTPM2_NO_WOLFCRYPT */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = NOT_COMPILED_IN;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)
    rc = TPM2_Boot_SecureROT_Example(NULL, argc, argv);
#else
    printf("Example not compiled in! Requires Wrapper and wolfCrypt\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* NO_MAIN_DRIVER */
