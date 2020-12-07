/* bench.c
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

/* This example shows benchmarks using the TPM2 wrapper API's in
    TPM2_Wrapper_Bench() below. */

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_TPM_BENCH)

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/tpm_test_keys.h>
#include <examples/bench/bench.h>

#include <stdio.h>

/* Configuration */
#define TPM2_BENCH_DURATION_SEC         1
#define TPM2_BENCH_DURATION_KEYGEN_SEC  15
static int gUseBase2 = 1;

static inline void bench_stats_start(int* count, double* start)
{
    *count = 0;
    *start = gettime_secs(1);
}

static inline int bench_stats_check(double start, int* count, double maxDurSec)
{
    (*count)++;
    return ((gettime_secs(0) - start) < maxDurSec);
}

/* countSz is number of bytes that 1 count represents. Normally bench_size,
 * except for AES direct that operates on AES_BLOCK_SIZE blocks */
static void bench_stats_sym_finish(const char* desc, int count, int countSz,
    double start)
{
    double total, persec = 0, blocks = count;
    const char* blockType;

    total = gettime_secs(0) - start;

    /* calculate actual bytes */
    blocks *= countSz;

    /* base 2 result */
    if (gUseBase2) {
        /* determine if we should show as KB or MB */
        if (blocks > (1024 * 1024)) {
            blocks /= (1024 * 1024);
            blockType = "MB";
        }
        else if (blocks > 1024) {
            blocks /= 1024; /* make KB */
            blockType = "KB";
        }
        else {
            blockType = "bytes";
        }
    }
    /* base 10 result */
    else {
        /* determine if we should show as kB or mB */
        if (blocks > (1000 * 1000)) {
            blocks /= (1000 * 1000);
            blockType = "mB";
        }
        else if (blocks > 1000) {
            blocks /= 1000; /* make kB */
            blockType = "kB";
        }
        else {
            blockType = "bytes";
        }
    }

    /* calculate blocks per second */
    if (total > 0) {
        persec = (1 / total) * blocks;
    }

    /* format and print to terminal */
    printf("%-16s %5.0f %s took %5.3f seconds, %8.3f %s/s\n",
        desc, blocks, blockType, total, persec, blockType);
}

static void bench_stats_asym_finish(const char* algo, int strength,
    const char* desc, int count, double start)
{
    double total, each = 0, opsSec, milliEach;

    total = gettime_secs(0) - start;
    if (count > 0)
        each  = total / count; /* per second  */
    opsSec = count / total;    /* ops second */
    milliEach = each * 1000;   /* milliseconds */

    printf("%-6s %5d %-9s %6d ops took %5.3f sec, avg %5.3f ms,"
        " %.3f ops/sec\n", algo, strength, desc,
        count, total, milliEach, opsSec);
}

static int bench_sym_hash(WOLFTPM2_DEV* dev, const char* desc, int algo,
    const byte* in, word32 inSz, byte* digest, word32 digestSz)
{
    int rc;
    int count;
    double start;
    WOLFTPM2_HASH hash;

    XMEMSET(&hash, 0, sizeof(hash));
    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_HashStart(dev, &hash, algo,
        (const byte*)gUsageAuth, sizeof(gUsageAuth)-1);
        if (rc != 0) goto exit;
        rc = wolfTPM2_HashUpdate(dev, &hash, in, inSz);
        if (rc != 0) goto exit;
        rc = wolfTPM2_HashFinish(dev, &hash, digest, &digestSz);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_sym_finish(desc, count, inSz, start);

exit:
    return rc;
}

static int bench_sym_aes(WOLFTPM2_DEV* dev, WOLFTPM2_KEY* storageKey,
    const char* desc, int algo, int keyBits, const byte* in, byte* out,
    word32 inOutSz, int isDecrypt)
{
    int rc;
    int count;
    double start;
    TPMT_PUBLIC publicTemplate;
    WOLFTPM2_KEY aesKey;

    XMEMSET(&aesKey, 0, sizeof(aesKey));
    rc = wolfTPM2_GetKeyTemplate_Symmetric(&publicTemplate, keyBits, algo,
        YES, YES);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(dev, &aesKey, &storageKey->handle,
        &publicTemplate, (byte*)gUsageAuth, sizeof(gUsageAuth)-1);
    if ((rc & TPM_RC_MODE) == TPM_RC_MODE || (rc & TPM_RC_VALUE) == TPM_RC_VALUE) {
        printf("Benchmark symmetric %s not supported!\n", desc);
        rc = 0; goto exit;
    }
    else if (rc != 0) goto exit;

    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_EncryptDecrypt(dev, &aesKey, in, out, inOutSz, NULL, 0,
            isDecrypt);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_sym_finish(desc, count, inOutSz, start);

exit:

    wolfTPM2_UnloadHandle(dev, &aesKey.handle);
    return rc;
}

static void usage(void)
{
    printf("Expected usage:\n");
    printf("./examples/bench/bench [-aes/xor]\n");
    printf("* -aes/xor: Use Parameter Encryption\n");
}

/******************************************************************************/
/* --- BEGIN Bench Wrapper -- */
/******************************************************************************/
int TPM2_Wrapper_Bench(void* userCtx)
{
    return TPM2_Wrapper_BenchArgs(userCtx, 0, NULL);
}

int TPM2_Wrapper_BenchArgs(void* userCtx, int argc, char *argv[])
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;
    WOLFTPM2_KEY rsaKey;
    WOLFTPM2_KEY eccKey;
    WOLFTPM2_BUFFER message;
    WOLFTPM2_BUFFER cipher;
    WOLFTPM2_BUFFER plain;
    TPMT_PUBLIC publicTemplate;
    TPM2B_ECC_POINT pubPoint;
    double start;
    int count;
    TPM_ALG_ID paramEncAlg = TPM_ALG_NULL;
    WOLFTPM2_SESSION tpmSession;

    if (argc >= 2) {
        if (XSTRNCMP(argv[1], "-?", 2) == 0 ||
            XSTRNCMP(argv[1], "-h", 2) == 0 ||
            XSTRNCMP(argv[1], "--help", 6) == 0) {
            usage();
            return 0;
        }
    }
    while (argc > 1) {
        if (XSTRNCMP(argv[argc-1], "-aes", 4) == 0) {
            paramEncAlg = TPM_ALG_CFB;
        }
        if (XSTRNCMP(argv[argc-1], "-xor", 4) == 0) {
            paramEncAlg = TPM_ALG_XOR;
        }
        argc--;
    }

    XMEMSET(&storageKey, 0, sizeof(storageKey));
    XMEMSET(&eccKey, 0, sizeof(eccKey));
    XMEMSET(&rsaKey, 0, sizeof(rsaKey));
    XMEMSET(&tpmSession, 0, sizeof(tpmSession));


    printf("TPM2 Benchmark using Wrapper API's\n");
    printf("\tUse Parameter Encryption: %s\n", TPM2_GetAlgName(paramEncAlg));

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, userCtx);
    if (rc != 0) return rc;

    /* See if primary storage key already exists */
    rc = getPrimaryStoragekey(&dev, &storageKey, TPM_ALG_RSA);
    if (rc != 0) goto exit;

    if (paramEncAlg != TPM_ALG_NULL) {
        /* Start an authenticated session (salted / unbound) with parameter encryption */
        rc = wolfTPM2_StartSession(&dev, &tpmSession, &storageKey, NULL,
            TPM_SE_HMAC, paramEncAlg);
        if (rc != 0) goto exit;
        printf("TPM2_StartAuthSession: sessionHandle 0x%x\n",
            (word32)tpmSession.handle.hndl);

        /* set session for authorization of the storage key */
        rc = wolfTPM2_SetAuthSession(&dev, 1, &tpmSession,
            (TPMA_SESSION_decrypt | TPMA_SESSION_encrypt | TPMA_SESSION_continueSession));
        if (rc != 0) goto exit;
    }

    /* RNG Benchmark */
    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_GetRandom(&dev, message.buffer, sizeof(message.buffer));
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_sym_finish("RNG", count, sizeof(message.buffer), start);

    /* AES Benchmarks */
    /* AES CBC */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CBC-enc", TPM_ALG_CBC, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CBC-dec", TPM_ALG_CBC, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CBC-enc", TPM_ALG_CBC, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CBC-dec", TPM_ALG_CBC, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;

    /* AES CTR */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CTR-enc", TPM_ALG_CTR, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CTR-dec", TPM_ALG_CTR, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CTR-enc", TPM_ALG_CTR, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CTR-dec", TPM_ALG_CTR, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;

    /* AES CFB */
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CFB-enc", TPM_ALG_CFB, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-128-CFB-dec", TPM_ALG_CFB, 128,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CFB-enc", TPM_ALG_CFB, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_ENCRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;
    rc = bench_sym_aes(&dev, &storageKey, "AES-256-CFB-dec", TPM_ALG_CFB, 256,
        message.buffer, cipher.buffer, sizeof(message.buffer), WOLFTPM2_DECRYPT);
    if (rc != 0 && rc != TPM_RC_COMMAND_CODE) goto exit;

    /* Hashing Benchmarks */
    /* SHA1 */
    rc = bench_sym_hash(&dev, "SHA1", TPM_ALG_SHA1, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA_DIGEST_SIZE);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA256 */
    rc = bench_sym_hash(&dev, "SHA256", TPM_ALG_SHA256, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA256_DIGEST_SIZE);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA384 */
    rc = bench_sym_hash(&dev, "SHA384", TPM_ALG_SHA384, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA384_DIGEST_SIZE);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;
    /* SHA512 */
    rc = bench_sym_hash(&dev, "SHA512", TPM_ALG_SHA512, message.buffer,
        sizeof(message.buffer), cipher.buffer, TPM_SHA512_DIGEST_SIZE);
    if (rc != 0 && (rc & TPM_RC_HASH) != TPM_RC_HASH) goto exit;


    /* Create RSA key for encrypt/decrypt */
    rc = wolfTPM2_GetKeyTemplate_RSA(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_sign | TPMA_OBJECT_noDA);
    if (rc != 0) goto exit;
    bench_stats_start(&count, &start);
    do {
        if (count > 0) {
            rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
            if (rc != 0) goto exit;
        }
        rc = wolfTPM2_CreateAndLoadKey(&dev, &rsaKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_KEYGEN_SEC));
    bench_stats_asym_finish("RSA", 2048, "key gen", count, start);

    /* Perform RSA encrypt / decrypt (no pad) */
    message.size = 256; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* encrypted data */
        rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_NULL,
            message.buffer, message.size, cipher.buffer, &cipher.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("RSA", 2048, "Public", count, start);

    bench_stats_start(&count, &start);
    do {
        plain.size = sizeof(plain.buffer);
        rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_NULL,
            cipher.buffer, cipher.size, plain.buffer, &plain.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("RSA", 2048, "Private", count, start);


    /* Perform RSA encrypt / decrypt (OAEP pad) */
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* encrypted data */
        rc = wolfTPM2_RsaEncrypt(&dev, &rsaKey, TPM_ALG_OAEP,
            message.buffer, message.size, cipher.buffer, &cipher.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("RSA", 2048, "Pub  OAEP", count, start);

    bench_stats_start(&count, &start);
    do {
        plain.size = sizeof(plain.buffer);
        rc = wolfTPM2_RsaDecrypt(&dev, &rsaKey, TPM_ALG_OAEP,
            cipher.buffer, cipher.size, plain.buffer, &plain.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("RSA", 2048, "Priv OAEP", count, start);

    rc = wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    if (rc != 0) goto exit;


    /* Create an ECC key for ECDSA */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_sign | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
    if (rc != 0) goto exit;
    bench_stats_start(&count, &start);
    do {
        if (count > 0) {
            rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
            if (rc != 0) goto exit;
        }
        rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
            &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("ECC", 256, "key gen", count, start);

    /* Perform sign / verify */
    message.size = TPM_SHA256_DIGEST_SIZE; /* test message 0x11,0x11,etc */
    XMEMSET(message.buffer, 0x11, message.size);

    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer); /* signature */
        rc = wolfTPM2_SignHash(&dev, &eccKey, message.buffer, message.size,
            cipher.buffer, &cipher.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("ECDSA", 256, "sign", count, start);

    bench_stats_start(&count, &start);
    do {
        rc = wolfTPM2_VerifyHash(&dev, &eccKey, cipher.buffer, cipher.size,
            message.buffer, message.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("ECDSA", 256, "verify", count, start);

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;


    /* Create an ECC key for ECDH */
    rc = wolfTPM2_GetKeyTemplate_ECC(&publicTemplate,
        TPMA_OBJECT_sensitiveDataOrigin | TPMA_OBJECT_userWithAuth |
        TPMA_OBJECT_decrypt | TPMA_OBJECT_noDA,
        TPM_ECC_NIST_P256, TPM_ALG_ECDH);
    if (rc != 0) goto exit;
    rc = wolfTPM2_CreateAndLoadKey(&dev, &eccKey, &storageKey.handle,
        &publicTemplate, (byte*)gKeyAuth, sizeof(gKeyAuth)-1);
    if (rc != 0) goto exit;

    /* Create ephemeral ECC key and generate a shared secret */
    bench_stats_start(&count, &start);
    do {
        cipher.size = sizeof(cipher.buffer);
        rc = wolfTPM2_ECDHGen(&dev, &eccKey, &pubPoint,
            cipher.buffer, &cipher.size);
        if (rc != 0) goto exit;
    } while (bench_stats_check(start, &count, TPM2_BENCH_DURATION_SEC));
    bench_stats_asym_finish("ECDHE", 256, "agree", count, start);

    rc = wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    if (rc != 0) goto exit;

exit:

    if (rc != 0) {
        printf("Failure 0x%x: %s\n", rc, wolfTPM2_GetRCString(rc));
    }

    wolfTPM2_UnloadHandle(&dev, &rsaKey.handle);
    wolfTPM2_UnloadHandle(&dev, &eccKey.handle);
    wolfTPM2_UnloadHandle(&dev, &tpmSession.handle);

    wolfTPM2_Cleanup(&dev);

    return rc;
}

/******************************************************************************/
/* --- END Bench Wrapper -- */
/******************************************************************************/

#endif /* !WOLFTPM2_NO_WRAPPER && !NO_TPM_BENCH */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
{
    int rc = -1;

#if !defined(WOLFTPM2_NO_WRAPPER) && !defined(NO_TPM_BENCH)
    rc = TPM2_Wrapper_BenchArgs(NULL, argc, argv);
#else
    printf("Wrapper code not compiled in\n");
    (void)argc;
    (void)argv;
#endif

    return rc;
}
#endif /* !NO_MAIN_DRIVER */
