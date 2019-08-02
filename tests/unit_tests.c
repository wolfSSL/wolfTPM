/* unit_tests.c
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

/* wolfTPM 2.0 unit tests */


#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>

#include <examples/tpm_io.h>
#include <examples/tpm_test.h>
#include <examples/wrap/wrap_test.h>

#include <stdio.h>

/* Test Fail Helpers */
#ifndef NO_ABORT
    #ifndef XABORT
    #include <stdlib.h>
    #define XABORT() abort()
    #endif
#else
    #undef  XABORT
    #define XABORT()
#endif

#define Fail(description, result) do {                                         \
    printf("\nERROR - %s line %d failed with:", __FILE__, __LINE__);           \
    printf("\n    expected: "); printf description;                            \
    printf("\n    result:   "); printf result; printf("\n\n");                 \
    XABORT();                                                                  \
} while(0)
#define Assert(test, description, result) if (!(test)) Fail(description, result)
#define AssertTrue(x)    Assert( (x), ("%s is true",     #x), (#x " => FALSE"))
#define AssertFalse(x)   Assert(!(x), ("%s is false",    #x), (#x " => TRUE"))
#define AssertNotNull(x) Assert( (x), ("%s is not null", #x), (#x " => NULL"))
#define AssertNull(x) do {                                                     \
    void* _x = (void *) (x);                                                   \
    Assert(!_x, ("%s is null", #x), (#x " => %p", _x));                        \
} while(0)
#define AssertInt(x, y, op, er) do {                                           \
    int _x = (int)x;                                                           \
    int _y = (int)y;                                                           \
    Assert(_x op _y, ("%s " #op " %s", #x, #y), ("%d " #er " %d", _x, _y));    \
} while(0)
#define AssertIntEQ(x, y) AssertInt(x, y, ==, !=)
#define AssertIntNE(x, y) AssertInt(x, y, !=, ==)
#define AssertIntGT(x, y) AssertInt(x, y,  >, <=)
#define AssertIntLT(x, y) AssertInt(x, y,  <, >=)
#define AssertIntGE(x, y) AssertInt(x, y, >=,  <)
#define AssertIntLE(x, y) AssertInt(x, y, <=,  >)
#define AssertStr(x, y, op, er) do {                                           \
    const char* _x = x;                                                        \
    const char* _y = y;                                                        \
    int   _z = (_x && _y) ? strcmp(_x, _y) : -1;                               \
    Assert(_z op 0, ("%s " #op " %s", #x, #y),                                 \
                                            ("\"%s\" " #er " \"%s\"", _x, _y));\
} while(0)
#define AssertStrEQ(x, y) AssertStr(x, y, ==, !=)
#define AssertStrNE(x, y) AssertStr(x, y, !=, ==)
#define AssertStrGT(x, y) AssertStr(x, y,  >, <=)
#define AssertStrLT(x, y) AssertStr(x, y,  <, >=)
#define AssertStrGE(x, y) AssertStr(x, y, >=,  <)
#define AssertStrLE(x, y) AssertStr(x, y, <=,  >)

#ifndef WOLFTPM2_NO_WRAPPER

static void test_wolfTPM2_Init(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Test arguments */
    rc = wolfTPM2_Init(NULL, TPM2_IoCb, NULL);
    AssertIntNE(rc, 0);
    rc = wolfTPM2_Init(&dev, NULL, NULL);
    AssertIntNE(rc, 0);

    /* Test success */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tInit:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}


/* test for WOLFTPM2_DEV restore */
static void test_wolfTPM2_OpenExisting(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    /* Init the TPM2 device */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test access to TPM by getting capabilities */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

    /* Perform cleanup, but don't shutdown TPM module */
    rc = wolfTPM2_Cleanup_ex(&dev, 0);
    AssertIntEQ(rc, 0);


    /* Restore TPM access */
    rc = wolfTPM2_OpenExisting(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test access to TPM by getting capabilities */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tOpen Existing:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

/* test for wolfTPM2_GetCapabilities */
static void test_wolfTPM2_GetCapabilities(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_CAPS caps;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test Arguments */
    rc = wolfTPM2_GetCapabilities(NULL, &caps);
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetCapabilities(&dev, NULL);
    AssertIntNE(rc, 0);

    /* Test success */
    rc = wolfTPM2_GetCapabilities(&dev, &caps);
    AssertIntEQ(rc, 0);

#ifdef DEBUG_WOLFTPM
    printf("Mfg %s (%d), Vendor %s, Fw %u.%u (%u), FIPS 140-2 %d, CC-EAL4 %d\n",
        caps.mfgStr, caps.mfg, caps.vendorStr, caps.fwVerMajor,
        caps.fwVerMinor, caps.fwVerVendor, caps.fips140_2, caps.cc_eal4);
#endif

    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tGet Capabilities:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

/* test for wolfTPM2_ReadPublicKey */
static void test_wolfTPM2_ReadPublicKey(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_KEY storageKey;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test arguments */
    rc = wolfTPM2_ReadPublicKey(NULL, &storageKey, TPM2_DEMO_STORAGE_KEY_HANDLE);
    AssertIntNE(rc, 0);
    rc = wolfTPM2_ReadPublicKey(&dev, NULL, TPM2_DEMO_STORAGE_KEY_HANDLE);
    AssertIntNE(rc, 0);

    /* Test success: read storage primary key */
    rc = wolfTPM2_ReadPublicKey(&dev, &storageKey,
        TPM2_DEMO_STORAGE_KEY_HANDLE);
    if (rc == TPM_RC_HANDLE) {
        rc = 0; /* okay if not found */
    }

    AssertIntEQ(rc, 0);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tRead Public Key:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_GetRandom(void)
{
    int rc;
    WOLFTPM2_DEV dev;
    WOLFTPM2_BUFFER rngData;

    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    /* Test arguments */
    rc = wolfTPM2_GetRandom(NULL, rngData.buffer, sizeof(rngData.buffer));
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetRandom(&dev, NULL, sizeof(rngData.buffer));
    AssertIntNE(rc, 0);
    rc = wolfTPM2_GetRandom(&dev, rngData.buffer, 0);
    AssertIntEQ(rc, 0);

    /* Test success */
    rc = wolfTPM2_GetRandom(&dev, rngData.buffer, sizeof(rngData.buffer));

    AssertIntEQ(rc, 0);
    wolfTPM2_Cleanup(&dev);

    printf("Test TPM Wrapper:\tGet Random:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

static void test_wolfTPM2_Cleanup(void)
{
    int rc;
    WOLFTPM2_DEV dev;

    /* Test arguments */
    rc = wolfTPM2_Cleanup(NULL);
    AssertIntNE(rc, 0);

    /* Test success */
    rc = wolfTPM2_Init(&dev, TPM2_IoCb, NULL);
    AssertIntEQ(rc, 0);

    rc = wolfTPM2_Cleanup(&dev);
    AssertIntEQ(rc, 0);

    printf("Test TPM Wrapper:\tCleanup:\t%s\n",
        rc == 0 ? "Passed" : "Failed");
}

#endif /* !WOLFTPM2_NO_WRAPPER */

#ifndef NO_MAIN_DRIVER
int main(int argc, char *argv[])
#else
int unit_tests(int argc, char *argv[])
#endif
{
    (void)argc;
    (void)argv;

#ifndef WOLFTPM2_NO_WRAPPER
    test_wolfTPM2_Init();
    test_wolfTPM2_OpenExisting();
    test_wolfTPM2_GetCapabilities();
    test_wolfTPM2_ReadPublicKey();
    test_wolfTPM2_GetRandom();
    test_wolfTPM2_Cleanup();
#endif /* !WOLFTPM2_NO_WRAPPER */

    return 0;
}
