/* spdm_ctrl_tests.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_spdm.h>

static int openCalls, defines, deletes, existing;
static int defineResult, deleteResult;
static int openResult = TPM_RC_FAILURE;
static int initCalls, initFails;
#ifdef WOLFSPDM_NATIONS
static int versionCalls;
#endif
#if defined(WOLFSPDM_NATIONS) || defined(WOLFSPDM_INFINEON)
static int capCalls;
#endif
static WOLFTPM2_SPDM_CTX mockSpdm;

static int mock_init(WOLFTPM2_DEV* dev, TPM2HalIoCb cb, void* user)
{
    (void)cb; (void)user;
    initCalls++;
    XMEMSET(dev, 0, sizeof(*dev));
    dev->spdmCtx = &mockSpdm;
    return initFails ? TPM_RC_FAILURE : 0;
}
static int mock_cleanup(WOLFTPM2_DEV* dev)
{ (void)dev; return 0; }
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS) || \
    defined(WOLFSPDM_INFINEON) || defined(WOLFTPM_SPDM_PSK)
static int mock_connected(WOLFTPM2_DEV* dev)
{ (void)dev; return 0; }
#endif
#ifdef WOLFSPDM_NATIONS
static int mock_mode(WOLFTPM2_DEV* dev)
{ (void)dev; return 0; }
#endif
#if defined(WOLFSPDM_NUVOTON) || defined(WOLFSPDM_NATIONS) || \
    defined(WOLFSPDM_INFINEON)
static int mock_tis(WOLFTPM2_SPDM_CTX* ctx)
{ (void)ctx; return 0; }
#endif
#ifdef WOLFSPDM_NATIONS
static int mock_version(WOLFSPDM_CTX* ctx)
{ (void)ctx; versionCalls++; return TPM_RC_FAILURE; }
#endif
#if defined(WOLFSPDM_NATIONS) || defined(WOLFSPDM_INFINEON)
static TPM_RC mock_cap(GetCapability_In* in, GetCapability_Out* out)
{ (void)in; (void)out; capCalls++; return TPM_RC_FAILURE; }
#endif
static TPM_RC mock_define(NV_DefineSpace_In* in)
{ (void)in; defines++; return defineResult; }
static int mock_open(WOLFTPM2_DEV* dev, WOLFTPM2_NV* nv,
    word32 index, const byte* auth, int authSz)
{
    (void)dev; (void)nv; (void)index; (void)auth; (void)authSz;
    openCalls++;
    if (existing) return TPM_RC_SUCCESS;
    return openCalls == 1 && defines == 0 ? TPM_RC_HANDLE : openResult;
}
static int mock_delete(WOLFTPM2_DEV* dev, WOLFTPM2_HANDLE* parent,
    word32 index)
{ (void)dev; (void)parent; (void)index; deletes++; return deleteResult; }
static int mock_auth(WOLFTPM2_DEV* dev, int index,
    const WOLFTPM2_HANDLE* handle)
{ (void)dev; (void)index; (void)handle; return 0; }

/* Replace only the example's hardware operations. The library and policy
 * digest calculation remain real; no board or TPM server is accessed. */
#define NO_MAIN_DRIVER
#define wolfTPM2_Init mock_init
#define wolfTPM2_Cleanup mock_cleanup
#define wolfTPM2_SpdmIsConnected mock_connected
#define wolfTPM2_SpdmSetNationsMode mock_mode
#define wolfTPM2_SPDM_SetTisIO mock_tis
#define wolfSPDM_GetVersion mock_version
#define TPM2_GetCapability mock_cap
#define TPM2_NV_DefineSpace mock_define
#define wolfTPM2_NVOpen mock_open
#define wolfTPM2_NVDeleteAuth mock_delete
#define wolfTPM2_SetAuthHandle mock_auth
#include "../examples/spdm/spdm_ctrl.c"

static int test_nv_cleanup(void)
{
    WOLFTPM2_DEV dev;
    WOLFTPM2_HANDLE parent;
    WOLFTPM2_NV nv;
    byte digest[TPM_SHA256_DIGEST_SIZE];
    int rc, owned;
    XMEMSET(&dev, 0, sizeof(dev));
    rc = ctrl_policy_nv(&dev);
    if (rc == 0 || defines != 1 || deletes != 1) return 1;
    existing = 1; defines = 0; deletes = 0;
    rc = ctrl_policy_nv(&dev);
    if (rc != TPM_RC_NV_DEFINED || defines != 0 || deletes != 0) return 1;
    puts("PASS: post-definition failure cleanup and existing-index protection");
    existing = 0; defines = 0; deletes = 0; openCalls = 0;
    deleteResult = TPM_RC_AUTH_FAIL;
    rc = ctrl_policy_nv(&dev);
    if (rc != TPM_RC_FAILURE || deletes != 1) return 1;
    XMEMSET(&parent, 0, sizeof(parent));
    XMEMSET(&nv, 0, sizeof(nv));
    XMEMSET(digest, 0, sizeof(digest));
    parent.hndl = TPM_RH_OWNER;
    owned = 1; defines = 0; deletes = 0;
    rc = ctrl_policy_nv_define(&dev, &parent, &nv,
        TPM2_DEMO_NVRAM_STORE_INDEX, 0, 1, digest, sizeof(digest), &owned);
    if (rc != TPM_RC_AUTH_FAIL || owned != 1 || defines != 0 || deletes != 1)
        return 1;
    deleteResult = 0; defineResult = TPM_RC_NV_DEFINED;
    owned = 1; defines = 0; deletes = 0;
    rc = ctrl_policy_nv_define(&dev, &parent, &nv,
        TPM2_DEMO_NVRAM_STORE_INDEX, 0, 1, digest, sizeof(digest), &owned);
    if (rc != TPM_RC_NV_DEFINED || owned != 0 || defines != 1 || deletes != 1)
        return 1;
    defineResult = 0; openResult = 0;
    owned = 1; defines = 0; deletes = 0;
    rc = ctrl_policy_nv_define(&dev, &parent, &nv,
        TPM2_DEMO_NVRAM_STORE_INDEX, 0, 1, digest, sizeof(digest), &owned);
    if (rc != 0 || owned != 1 || defines != 1 || deletes != 1) return 1;
    puts("PASS: owned-index replacement, failed deletion/redefinition and cleanup errors");
    return 0;
}

static int test_vendor_dispatch(void)
{
#if defined(WOLFSPDM_NATIONS) || defined(WOLFSPDM_INFINEON)
    char program[] = "spdm_ctrl";
#endif
#if defined(WOLFSPDM_NATIONS) && defined(WOLFSPDM_NUVOTON)
    char setOption[] = "--psk-set";
    char clearOption[] = "--psk-clear";
#endif
#if defined(WOLFSPDM_NATIONS) && defined(WOLFSPDM_NUVOTON)
    char nuvoton[] = "--vendor=nuvoton";
    char shortPsk[] = "AABB";
    char shortAuth[] = "CCDD";
    char* setNuvoton[] = { program, nuvoton, setOption, shortPsk, shortAuth };
    char* clearNuvoton[] = { program, nuvoton, clearOption, shortAuth };
#endif
#if defined(WOLFSPDM_NATIONS) && !defined(WOLFSPDM_NUVOTON) && \
    !defined(WOLFSPDM_INFINEON)
    char statusOption[] = "--status";
    char pubkeyOption[] = "--get-pubkey";
    char capsOption[] = "--caps184";
    char* status[] = { program, statusOption };
    char* pubkey[] = { program, pubkeyOption };
    char* caps[] = { program, capsOption };
#endif
#ifdef WOLFSPDM_INFINEON
    char infineon[] = "--vendor=slb9678";
    char infStatus[] = "--status";
    char* statusFirst[] = { program, infineon, infStatus };
    char* statusLast[] = { program, infStatus, infineon };
#endif
#if defined(WOLFSPDM_NATIONS) && defined(WOLFSPDM_INFINEON)
    char identityOption[] = "--identity-key-set";
    char* identity[] = { program, infineon, identityOption };
#endif
#if defined(WOLFSPDM_NATIONS) && !defined(WOLFSPDM_NUVOTON) && \
    !defined(WOLFSPDM_INFINEON)
    (void)TPM2_SPDM_Ctrl(NULL, 2, status);
    if (capCalls == 0 || versionCalls == 0) return 1;
    versionCalls = 0;
    (void)TPM2_SPDM_Ctrl(NULL, 2, pubkey);
    if (versionCalls == 0) return 1;
    capCalls = 0;
    (void)TPM2_SPDM_Ctrl(NULL, 2, caps);
    if (capCalls == 0) return 1;
    puts("PASS: Nations-only default status, identity and capability dispatch");
#endif
#if defined(WOLFSPDM_NATIONS) && defined(WOLFSPDM_INFINEON)
    initFails = 1;
    initCalls = 0; (void)TPM2_SPDM_Ctrl(NULL, 3, identity);
    if (initCalls != 0) return 1;
    puts("PASS: Infineon selector does not claim the Nations identity option");
#endif
#ifdef WOLFSPDM_INFINEON
    /* The selector may appear before or after the command it applies to. */
    initFails = 0;
    capCalls = 0;
    if (TPM2_SPDM_Ctrl(NULL, 3, statusFirst) == 0 || capCalls != 1) return 1;
    if (TPM2_SPDM_Ctrl(NULL, 3, statusLast) == 0 || capCalls != 2) return 1;
    puts("PASS: Infineon status dispatch in both option orders");
#endif
#if defined(WOLFSPDM_NATIONS) && defined(WOLFSPDM_NUVOTON)
    initFails = 1;
    initCalls = 0; (void)TPM2_SPDM_Ctrl(NULL, 5, setNuvoton);
    if (initCalls != 0) return 1;
    initCalls = 0; (void)TPM2_SPDM_Ctrl(NULL, 4, clearNuvoton);
    if (initCalls != 0) return 1;
    puts("PASS: Nuvoton rejects PSK provisioning before initialization");
#endif
    return 0;
}

int main(void)
{
    int rc;
    rc = test_nv_cleanup();
    if (rc == 0) rc = test_vendor_dispatch();
    if (rc != 0) puts("FAIL: SPDM control regression");
    return rc;
}
