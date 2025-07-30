/* secure_rot.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Example for using TPM for secure boot root of trust
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(WOLFTPM2_NO_WOLFCRYPT)

#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/boot/boot.h>

#include <wolfssl/wolfcrypt/hash.h>

/******************************************************************************/
/* --- BEGIN TPM NVRAM Secure Boot Root of Trust Example -- */
/******************************************************************************/
static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/boot/secure_rot [-nvindex] [-write=/-hash=] [-authhex=/-authstr=] [-sha384] [-lock]\n");
    printf("* -nvindex=[handle] (default 0x%x)\n", TPM2_DEMO_NV_SECURE_ROT_INDEX);
    printf("* -hash=hash: Hex string digest to write\n");
    printf("* -write=filename: DER formatted public key to write\n");
    printf("* -authstr=password/-authhex=hexstring: Optional password for NV\n");
    printf("* -sha384: Use SHA2-384 (default is SHA2-256)\n");
    printf("* -lock: Lock the write\n");
    printf("\nExamples:\n");
    printf("\t./examples/boot/secure_rot -write=./certs/example-ecc256-key-pub.der\n");
    printf("\t./examples/boot/secure_rot -sha384 -hash="
        "e77dd3112a27948a3f2d87f32dc69ebe"
        "ed0b3344c5d7726f5742f4f0c0f451aa"
        "be4213f8b3b986639e69ed0ea8b49d94\n"
    );
}

int TPM2_Boot_SecureROT_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_SESSION tpmSession;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    TPMS_NV_PUBLIC nvPublic;
    word32 nvAttributes;
    /* always use AES CFB parameter encryption */
    int paramEncAlg = TPM_ALG_CFB;
    /* use platform handle to prevent TPM2_Clear from removing */
    TPMI_RH_NV_AUTH authHandle = TPM_RH_PLATFORM;
    const char* filename = NULL;
    word32 nvIndex = TPM2_DEMO_NV_SECURE_ROT_INDEX;
    int doWrite = 0, doLock = 0;
    byte* buf = NULL;
    size_t bufSz = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_SHA256;
    byte digest[WC_MAX_DIGEST_SIZE];
    int digestSz = 0;
    byte authBuf[WC_SHA256_DIGEST_SIZE];
    int authBufSz = 0;

    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(authBuf, 0, sizeof(authBuf));
    XMEMSET(digest, 0, sizeof(digest));
    XMEMSET(&nv, 0, sizeof(nv));

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
            const char* nvIndexStr = argv[argc-1] + XSTRLEN("-nvindex=");
            nvIndex = (word32)XSTRTOUL(nvIndexStr, NULL, 0);
            if (!(authHandle == TPM_RH_PLATFORM && (
                    nvIndex > TPM_20_PLATFORM_MFG_NV_SPACE &&
                    nvIndex < TPM_20_OWNER_NV_SPACE)) &&
                !(authHandle == TPM_RH_OWNER && (
                    nvIndex > TPM_20_OWNER_NV_SPACE &&
                    nvIndex < TPM_20_TCG_NV_SPACE)))
            {
                fprintf(stderr, "Invalid NV Index %s\n", nvIndexStr);
                fprintf(stderr, "\tPlatform Range: 0x%x -> 0x%x\n",
                    TPM_20_PLATFORM_MFG_NV_SPACE, TPM_20_OWNER_NV_SPACE);
                fprintf(stderr, "\tOwner Range: 0x%x -> 0x%x\n",
                    TPM_20_OWNER_NV_SPACE, TPM_20_TCG_NV_SPACE);
                usage();
                return -1;
            }
        }
        else if (XSTRNCMP(argv[argc-1], "-write=", XSTRLEN("-write=")) == 0) {
            doWrite = 1;
            filename = argv[argc-1] + XSTRLEN("-write=");
        }
        else if (XSTRNCMP(argv[argc-1], "-hash=", XSTRLEN("-hash=")) == 0) {
            const char* hashHexStr = argv[argc-1] + XSTRLEN("-hash=");
            int hashHexStrLen = (int)XSTRLEN(hashHexStr);
            if (hashHexStrLen > (int)sizeof(digest)*2+1)
                digestSz = -1;
            else
                digestSz = hexToByte(hashHexStr, digest, hashHexStrLen);
            if (digestSz <= 0) {
                fprintf(stderr, "Invalid hash length\n");
                usage();
                return -1;
            }
            doWrite = 1;
        }
        else if (XSTRNCMP(argv[argc-1], "-authstr=", XSTRLEN("-authstr=")) == 0) {
            const char* authHexStr = argv[argc-1] + XSTRLEN("-authstr=");
            authBufSz = (int)XSTRLEN(authHexStr);
            if (authBufSz > (int)sizeof(authBuf))
                authBufSz = (word32)sizeof(authBuf);
            XMEMCPY(authBuf, authHexStr, authBufSz);
        }
        else if (XSTRNCMP(argv[argc-1], "-authhex=", XSTRLEN("-authhex=")) == 0) {
            const char* authHexStr = argv[argc-1] + XSTRLEN("-authhex=");
            int authHexStrLen = (int)XSTRLEN(authHexStr);
            if (authHexStrLen > (int)sizeof(authBuf)*2+1)
                authBufSz = -1;
            else
                authBufSz = hexToByte(authHexStr, authBuf, authHexStrLen);
            if (authBufSz < 0) {
                fprintf(stderr, "Invalid auth length\n");
                usage();
                return -1;
            }
        }
        else if (XSTRCMP(argv[argc-1], "-sha384") == 0) {
            hashType = WC_HASH_TYPE_SHA384;
        }
        else if (XSTRCMP(argv[argc-1], "-lock") == 0) {
            doLock = 1;
        }
        else {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    };

    /* setup the parent handle OWNER/PLATFORM */
    parent.hndl = authHandle;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("\nwolfTPM2_Init failed\n");
        goto exit;
    }

    /* Start TPM session for parameter encryption */
    printf("Parameter Encryption: Enabled %s and HMAC\n\n",
        TPM2_GetAlgName(paramEncAlg));
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

    printf("NV Auth (%d)\n", authBufSz);
    TPM2_PrintBin(authBuf, authBufSz);

    /* Open file */
    if (doWrite) {
        if (filename == NULL) {
            printf("Storing hash to NV index 0x%x\n\n", nvIndex);
        }
        else {
            printf("Storing hash of public key file %s to NV index 0x%x\n\n",
                filename, nvIndex);

            rc = loadFile(filename, &buf, &bufSz);
            if (rc == 0) {
                /* hash public key */
                digestSz = wc_HashGetDigestSize(hashType);
                rc = wc_Hash(hashType, buf, (word32)bufSz, digest, digestSz);
            }
        }

        if (rc == 0) {
            printf("Public Key Hash (%d)\n", digestSz);
            TPM2_PrintBin(digest, digestSz);
        }
        if (rc == 0) {
            /* Get NV attributes */
            rc = wolfTPM2_GetNvAttributesTemplate(parent.hndl, &nvAttributes);
        }
        if (rc == 0) {
            /* allow this NV to be locked */
            nvAttributes |= TPMA_NV_WRITEDEFINE;

            /* Create NV */
            rc = wolfTPM2_NVCreateAuth(&dev, &parent, &nv, nvIndex,
                nvAttributes, digestSz, authBuf, authBufSz);
            if (rc == TPM_RC_NV_DEFINED) {
                printf("Warning: NV Index 0x%x already exists!\n", nvIndex);
                rc = 0;
            }
            wolfTPM2_SetAuthHandle(&dev, 0, &nv.handle);
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
    nv.handle.auth.size = authBufSz;
    XMEMCPY(nv.handle.auth.buffer, authBuf, nv.handle.auth.size);

    /* Read the NV Index publicArea to have up to date NV Index Name */
    rc = wolfTPM2_NVReadPublic(&dev, nvIndex, &nvPublic);
    if (rc == 0) {
        digestSz = nvPublic.dataSize;
    }

    /* Read access */
    printf("Reading NV 0x%x public key hash\n", nvIndex);
    rc = wolfTPM2_NVReadAuth(&dev, &nv, nvIndex, digest, (word32*)&digestSz, 0);
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
