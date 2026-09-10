/* unseal.c
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

/* This example demonstrates how to extract the data from a TPM seal object */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_wrap.h>

#include <stdio.h>
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES) && \
    !defined(WOLFTPM_CUSTOM_STDIO) && \
    (defined(WOLFTPM2_NO_WOLFCRYPT) || defined(XFDOPEN)) && \
    (defined(__linux__) || defined(__APPLE__) || defined(__unix__))
    #define WOLFTPM_UNSEAL_POSIX_FILE_IO
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
    #ifndef XFDOPEN
        #define XFDOPEN fdopen
    #endif
    #ifndef XCLOSE
        #define XCLOSE close
    #endif
#endif

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_FILESYSTEM)

#include <examples/seal/seal.h>
#include <hal/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>


/******************************************************************************/
/* --- BEGIN TPM2.0 Unseal example --- */
/******************************************************************************/

#ifndef NO_WRITE_TEMP_FILES
static XFILE openPrivateFileWrite(const char* filename)
{
#ifdef WOLFTPM_UNSEAL_POSIX_FILE_IO
    int fd;
    int openFlags;
    struct stat fileStat;
    #ifndef O_NOFOLLOW
        struct stat pathStat;
    #endif
    XFILE fp;

    openFlags = O_WRONLY | O_CREAT;
    #ifdef O_CLOEXEC
        openFlags |= O_CLOEXEC;
    #endif
    #ifdef O_NOFOLLOW
        openFlags |= O_NOFOLLOW;
    #endif

    fd = open(filename, openFlags, S_IRUSR | S_IWUSR);
    if (fd < 0)
        return XBADFILE;

    #ifndef O_NOFOLLOW
        /* Confirm open() did not follow a link before changing the file. */
        if (lstat(filename, &pathStat) != 0)
            goto exit;
    #endif

    /* Validate before truncating so linked and special files stay untouched. */
    if (fstat(fd, &fileStat) != 0 || !S_ISREG(fileStat.st_mode) ||
            fileStat.st_uid != geteuid() || fileStat.st_nlink != 1)
        goto exit;

    #ifndef O_NOFOLLOW
        if (!S_ISREG(pathStat.st_mode) ||
                pathStat.st_dev != fileStat.st_dev ||
                pathStat.st_ino != fileStat.st_ino)
            goto exit;
    #endif

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0 || ftruncate(fd, 0) != 0)
        goto exit;

    fp = XFDOPEN(fd, "wb");
    if (fp == XBADFILE)
        goto exit;
    return fp;

exit:
    (void)XCLOSE(fd);
    return XBADFILE;
#else
    /* The custom filesystem controls creation permissions on this path. */
    return XFOPEN(filename, "wb");
#endif
}
#endif /* !NO_WRITE_TEMP_FILES */

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/seal/unseal [filename] [inkey_filename]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
    printf("* filename: Output for unsealed data (default: unseal.bin)\n");
    printf("* inkey_filename: File with sealed keyed hashed object (keyblob.bin)\n");
    printf("Demo usage, without arguments, uses keyblob.bin file input.\n");
}

int TPM2_Unseal_Example(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEYBLOB newKey;
    WOLFTPM2_KEY storage; /* SRK */
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;
    const char *filename = "unseal.bin";
    const char *inkeyfilename = "keyblob.bin";
#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    XFILE fp = NULL;
    size_t len;
#endif
    Unseal_In cmdIn_unseal;
    Unseal_Out cmdOut_unseal;

    XMEMSET(&storage, 0, sizeof(storage));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));
    XMEMSET(&cmdIn_unseal, 0, sizeof(cmdIn_unseal));
    XMEMSET(&cmdOut_unseal, 0, sizeof(cmdOut_unseal));
    XMEMSET(&newKey, 0, sizeof(newKey));

    if (argc >= 2) {
        if (XSTRCMP(argv[1], "-?") == 0 ||
            XSTRCMP(argv[1], "-h") == 0 ||
            XSTRCMP(argv[1], "--help") == 0) {
            usage();
            return 0;
        }

        if (argv[1][0] != '-') {
            filename = argv[1];
        }

        if (argc >= 3 && argv[2][0] != '-') {
           inkeyfilename = argv[2];
        }
    }
    while (argc > 1) {
        if (XSTRCMP(argv[argc-1], "-aes") == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        else if (XSTRCMP(argv[argc-1], "-xor") == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        else if (argv[argc-1][0] == '-') {
            printf("Warning: Unrecognized option: %s\n", argv[argc-1]);
        }
        argc--;
    }

    printf("TPM2.0 Simple Unseal example\n");
    printf("\tKey Blob: %s\n", inkeyfilename);
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));


    printf("Example how to unseal data using TPM2.0\n");
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_Init failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("wolfTPM2_Init: success\n");

    rc = getPrimaryStoragekey(&dev, &storage, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storage, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;

    }

    rc = readKeyBlob(inkeyfilename, &newKey);
    if (rc != 0) goto exit;

    rc = wolfTPM2_LoadKey(&dev, &newKey, &storage.handle);
    if (rc != TPM_RC_SUCCESS) {
        printf("wolfTPM2_LoadKey failed\n");
        goto exit;
    }
    printf("Loaded key to 0x%x\n",
        (word32)newKey.handle.hndl);

    /* Set authorization for using the seal key */
    newKey.handle.auth.size = (int)sizeof(gKeyAuth) - 1;
    XMEMCPY(newKey.handle.auth.buffer, gKeyAuth, newKey.handle.auth.size);
    wolfTPM2_SetAuthHandle(&dev, 0, &newKey.handle);

    cmdIn_unseal.itemHandle = newKey.handle.hndl;

    rc = TPM2_Unseal(&cmdIn_unseal, &cmdOut_unseal);
    if (rc != TPM_RC_SUCCESS) {
        printf("TPM2_Unseal failed 0x%x: %s\n", rc, TPM2_GetRCString(rc));
        goto exit;
    }
    printf("Unsealing succeeded\n");

#ifdef DEBUG_WOLFTPM
    printf("Unsealed data:\n");
    TPM2_PrintBin(cmdOut_unseal.outData.buffer, cmdOut_unseal.outData.size);
#endif

#if !defined(NO_FILESYSTEM) && !defined(NO_WRITE_TEMP_FILES)
    /* Output the unsealed data to a file */
    if (filename) {
        fp = openPrivateFileWrite(filename);
        if (fp == XBADFILE) {
            printf("Error opening %s for writing.\n", filename);
            rc = TPM_RC_FAILURE;
            goto exit;
        }
        len = XFWRITE(cmdOut_unseal.outData.buffer, 1,
            cmdOut_unseal.outData.size, fp);
        XFCLOSE(fp);

        if (len != cmdOut_unseal.outData.size) {
            printf("Error while writing the unsealed data to a file.\n");
            rc = TPM_RC_FAILURE;
            goto exit;
        }
        printf("Stored unsealed data to file = %s\n", filename);
    }
#else
    printf("Unable to store unsealed data to a file. Enable wolfcrypt support.\n");
    (void)filename;
#endif

    /* Remove the auth for loaded TPM seal object */
    wolfTPM2_UnsetAuth(&dev, 0);

exit:
    wolfTPM2_UnloadHandle(&dev, &storage.handle);
    wolfTPM2_UnloadHandle(&dev, &newKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);
    return rc;
}

/******************************************************************************/
/* --- END TPM2.0 Unseal example --- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_FILESYSTEM)
    rc = TPM2_Unseal_Example(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif /* !WOLFTPM2_NO_WRAPPER */

    return rc;
}
#endif
