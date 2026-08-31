/* fwtpm_hal_unit_tests.c
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

/* Isolated tests for the POSIX fwTPM client HAL. The production source is
 * included directly so each test can use PID-specific endpoint names without
 * colliding with a running fwTPM server. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
/* Keep this before sem_open interposition below so the macro cannot rewrite
 * the system declaration into a conflicting TestSemOpen prototype. */
#include <semaphore.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static char gTestShmPath[96];
static char gTestAuxPath[96];
static char gTestSemCmdBase[16];
static char gTestSemRspBase[16];
static int gSwapAfterSemOpen;
static int gSemOpenCount;
static int gSwapFailed;

static int CreateEndpointFile(const char* path, mode_t mode,
    off_t sizeAdjust, UINT32 magic, UINT32 version);
static int ReplaceEndpoint(void);

#define FWTPM_TIS_SHM_PATH gTestShmPath
#define FWTPM_TIS_SEM_CMD  gTestSemCmdBase
#define FWTPM_TIS_SEM_RSP  gTestSemRspBase
#define WOLFTPM_INCLUDE_IO_FILE

#include "../hal/tpm_io.h"
#include <wolftpm/fwtpm/fwtpm_tis.h>

static char gTestSemCmd[FWTPM_TIS_SEM_NAME_SIZE];
static char gTestSemRsp[FWTPM_TIS_SEM_NAME_SIZE];

/* tpm_io_fwtpm.c normally gets this helper from libwolftpm. */
static void TestForceZero(void* mem, word32 len)
{
    volatile byte* p = (volatile byte*)mem;

    while (len-- > 0U) {
        *p++ = 0;
    }
}

#include "../src/fwtpm/fwtpm_tis_sem.c"

static sem_t* TestSemOpen(const char* name, int oflag, ...)
{
    sem_t* sem = sem_open(name, oflag);

    if (sem != SEM_FAILED && gSwapAfterSemOpen) {
        gSemOpenCount++;
        if (gSemOpenCount == 2 && ReplaceEndpoint() != 0) {
            gSwapFailed = 1;
        }
    }
    return sem;
}

#define TPM2_ForceZero TestForceZero
#define sem_open TestSemOpen
#include "../hal/tpm_io_fwtpm.c"
#undef sem_open
#undef TPM2_ForceZero

static void CleanupEndpoint(void)
{
    (void)sem_unlink(gTestSemRsp);
    (void)sem_unlink(gTestSemCmd);
    (void)unlink(gTestShmPath);
    (void)unlink(gTestAuxPath);
    gSwapAfterSemOpen = 0;
    gSemOpenCount = 0;
    gSwapFailed = 0;
}

static int CreateEndpointFile(const char* path, mode_t mode,
    off_t sizeAdjust, UINT32 magic, UINT32 version)
{
    FWTPM_TIS_REGS* regs;
    off_t fileSize = (off_t)sizeof(FWTPM_TIS_REGS) + sizeAdjust;
    int fd = -1;
    int rc = -1;

    if (fileSize <= 0) {
        return -1;
    }
    fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 || fchmod(fd, mode) != 0 ||
            ftruncate(fd, fileSize) != 0) {
        goto exit;
    }

    if (fileSize >= (off_t)sizeof(FWTPM_TIS_REGS)) {
        regs = (FWTPM_TIS_REGS*)mmap(NULL, sizeof(FWTPM_TIS_REGS),
            PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (regs == MAP_FAILED) {
            goto exit;
        }
        XMEMSET(regs, 0, sizeof(*regs));
        regs->magic = magic;
        regs->version = version;
        (void)munmap(regs, sizeof(FWTPM_TIS_REGS));
    }

    rc = 0;

exit:
    if (fd >= 0) {
        (void)close(fd);
    }
    if (rc != 0) {
        (void)unlink(path);
    }
    return rc;
}

static int ReplaceEndpoint(void)
{
    (void)unlink(gTestAuxPath);
    if (CreateEndpointFile(gTestAuxPath, 0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0) {
        return -1;
    }
    if (rename(gTestAuxPath, gTestShmPath) != 0) {
        (void)unlink(gTestAuxPath);
        return -1;
    }
    return 0;
}

static int CreateEndpoint(mode_t mode, off_t sizeAdjust, UINT32 magic,
    UINT32 version)
{
    sem_t* semCmd = SEM_FAILED;
    sem_t* semRsp = SEM_FAILED;
    int rc = -1;

    CleanupEndpoint();
    if (FWTPM_TIS_MakeSemNames((UINT64)geteuid(), gTestSemCmd,
            sizeof(gTestSemCmd), gTestSemRsp, sizeof(gTestSemRsp)) != 0 ||
            CreateEndpointFile(gTestShmPath, mode, sizeAdjust, magic,
            version) != 0) {
        goto exit;
    }

    semCmd = sem_open(gTestSemCmd, O_CREAT | O_EXCL, 0600, 0);
    semRsp = sem_open(gTestSemRsp, O_CREAT | O_EXCL, 0600, 0);
    if (semCmd == SEM_FAILED || semRsp == SEM_FAILED) {
        goto exit;
    }
    rc = 0;

exit:
    if (semRsp != SEM_FAILED) {
        (void)sem_close(semRsp);
    }
    if (semCmd != SEM_FAILED) {
        (void)sem_close(semCmd);
    }
    if (rc != 0) {
        CleanupEndpoint();
    }
    return rc;
}

static int ExpectRejected(const char* name, mode_t mode, off_t sizeAdjust,
    UINT32 magic, UINT32 version)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    if (CreateEndpoint(mode, sizeAdjust, magic, version) != 0) {
        printf("FAIL: %s setup\n", name);
        return 1;
    }

    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc == TPM_RC_SUCCESS) {
        FWTPM_TIS_ClientDisconnect(&client);
        printf("FAIL: accepted %s endpoint\n", name);
        CleanupEndpoint();
        return 1;
    }

    printf("PASS: rejected %s endpoint\n", name);
    CleanupEndpoint();
    return 0;
}

static int ExpectAccepted(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    /* Default UID-derived names are covered by fwtpm_tis_sem_unit.test. */
    if (CreateEndpoint(0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0) {
        printf("FAIL: trusted endpoint setup\n");
        return 1;
    }

    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc != TPM_RC_SUCCESS) {
        printf("FAIL: rejected trusted endpoint\n");
        CleanupEndpoint();
        return 1;
    }

    FWTPM_TIS_ClientDisconnect(&client);
    printf("PASS: accepted trusted endpoint\n");
    CleanupEndpoint();
    return 0;
}

static int ExpectDisconnectZeroized(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    FWTPM_TIS_REGS* observer = MAP_FAILED;
    int observerFd = -1;
    int rc;
    int idx;
    int failed = 0;

    if (CreateEndpoint(0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0) {
        printf("FAIL: disconnect zeroization setup\n");
        return 1;
    }
    observerFd = open(gTestShmPath, O_RDWR);
    if (observerFd < 0) {
        failed = 1;
        goto exit;
    }
    observer = (FWTPM_TIS_REGS*)mmap(NULL, sizeof(*observer),
        PROT_READ | PROT_WRITE, MAP_SHARED, observerFd, 0);
    if (observer == MAP_FAILED) {
        failed = 1;
        goto exit;
    }

    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc != TPM_RC_SUCCESS) {
        failed = 1;
        goto exit;
    }
    XMEMSET(client.shm->reg_data, 0xA5, sizeof(client.shm->reg_data));
    FWTPM_TIS_ClientDisconnect(&client);

    for (idx = 0; idx < (int)sizeof(observer->reg_data); idx++) {
        if (observer->reg_data[idx] != 0U) {
            failed = 1;
            break;
        }
    }

exit:
    if (observer != MAP_FAILED) {
        (void)munmap(observer, sizeof(*observer));
    }
    if (observerFd >= 0) {
        (void)close(observerFd);
    }
    printf("%s: disconnect zeroized shared register data\n",
        failed ? "FAIL" : "PASS");
    CleanupEndpoint();
    return failed;
}

static int ExpectSymlinkRejected(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    if (CreateEndpoint(0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0 ||
            rename(gTestShmPath, gTestAuxPath) != 0 ||
            symlink(gTestAuxPath, gTestShmPath) != 0) {
        printf("FAIL: symlink setup\n");
        CleanupEndpoint();
        return 1;
    }
    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc == TPM_RC_SUCCESS) {
        FWTPM_TIS_ClientDisconnect(&client);
        printf("FAIL: accepted symlink endpoint\n");
        CleanupEndpoint();
        return 1;
    }
    printf("PASS: rejected symlink endpoint\n");
    CleanupEndpoint();
    return 0;
}

static int ExpectHardlinkRejected(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    if (CreateEndpoint(0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0 ||
            link(gTestShmPath, gTestAuxPath) != 0) {
        printf("FAIL: hardlink setup\n");
        CleanupEndpoint();
        return 1;
    }
    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc == TPM_RC_SUCCESS) {
        FWTPM_TIS_ClientDisconnect(&client);
        printf("FAIL: accepted hardlink endpoint\n");
        CleanupEndpoint();
        return 1;
    }
    printf("PASS: rejected hardlink endpoint\n");
    CleanupEndpoint();
    return 0;
}

static int ExpectFifoRejected(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    CleanupEndpoint();
    if (mkfifo(gTestShmPath, 0600) != 0) {
        printf("FAIL: FIFO setup\n");
        return 1;
    }
    rc = FWTPM_TIS_ClientConnect(&client);
    if (rc == TPM_RC_SUCCESS) {
        FWTPM_TIS_ClientDisconnect(&client);
        printf("FAIL: accepted FIFO endpoint\n");
        CleanupEndpoint();
        return 1;
    }
    printf("PASS: rejected FIFO endpoint\n");
    CleanupEndpoint();
    return 0;
}

static int ExpectSwapRejected(void)
{
    FWTPM_TIS_CLIENT_CTX client;
    int rc;

    if (CreateEndpoint(0600, 0, FWTPM_TIS_MAGIC,
            FWTPM_TIS_VERSION) != 0) {
        printf("FAIL: pathname-swap setup\n");
        return 1;
    }
    gSwapAfterSemOpen = 1;
    rc = FWTPM_TIS_ClientConnect(&client);
    if (gSwapFailed || gSemOpenCount != 2 || rc == TPM_RC_SUCCESS) {
        if (rc == TPM_RC_SUCCESS) {
            FWTPM_TIS_ClientDisconnect(&client);
        }
        printf("FAIL: accepted or failed to exercise pathname swap\n");
        CleanupEndpoint();
        return 1;
    }
    printf("PASS: rejected endpoint swapped after semaphore open\n");
    CleanupEndpoint();
    return 0;
}

static int TestMetadataValidation(void)
{
    struct stat st;
    uid_t expectedUid = geteuid();

    XMEMSET(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    st.st_uid = expectedUid;
    st.st_nlink = 1;
    st.st_size = (off_t)sizeof(FWTPM_TIS_REGS);
    if (FWTPM_TIS_ClientValidateShm(&st) != TPM_RC_SUCCESS) {
        printf("FAIL: rejected trusted metadata\n");
        return 1;
    }

    st.st_uid = (uid_t)(expectedUid + 1U);
    if (FWTPM_TIS_ClientValidateShm(&st) == TPM_RC_SUCCESS) {
        printf("FAIL: accepted wrong-owner metadata\n");
        return 1;
    }
    st.st_uid = expectedUid;
    st.st_mode = S_IFIFO | S_IRUSR | S_IWUSR;
    if (FWTPM_TIS_ClientValidateShm(&st) == TPM_RC_SUCCESS) {
        printf("FAIL: accepted non-regular metadata\n");
        return 1;
    }
    st.st_mode = S_IFREG | S_IRUSR | S_IWUSR;
    st.st_nlink = 2;
    if (FWTPM_TIS_ClientValidateShm(&st) == TPM_RC_SUCCESS) {
        printf("FAIL: accepted multiply-linked metadata\n");
        return 1;
    }
    printf("PASS: validated endpoint metadata\n");
    return 0;
}

static int TestCustomSemPrefixes(void)
{
    char semCmd[FWTPM_TIS_SEM_NAME_SIZE];
    char semRsp[FWTPM_TIS_SEM_NAME_SIZE];
    char otherCmd[FWTPM_TIS_SEM_NAME_SIZE];
    char otherRsp[FWTPM_TIS_SEM_NAME_SIZE];
    UINT64 ownerUid = (UINT64)geteuid();
    size_t cmdPrefixSz = XSTRLEN(gTestSemCmdBase);
    size_t rspPrefixSz = XSTRLEN(gTestSemRspBase);

    if (FWTPM_TIS_MakeSemNames(ownerUid, semCmd, sizeof(semCmd), semRsp,
            sizeof(semRsp)) != 0 ||
            FWTPM_TIS_MakeSemNames(ownerUid + 1U, otherCmd,
                sizeof(otherCmd), otherRsp, sizeof(otherRsp)) != 0 ||
            XSTRNCMP(semCmd, gTestSemCmdBase, cmdPrefixSz) != 0 ||
            XSTRNCMP(semRsp, gTestSemRspBase, rspPrefixSz) != 0 ||
            semCmd[cmdPrefixSz] != '-' || semRsp[rspPrefixSz] != '-' ||
            XSTRCMP(semCmd, otherCmd) == 0 ||
            XSTRCMP(semRsp, otherRsp) == 0) {
        printf("FAIL: caller semaphore prefixes lost UID namespacing\n");
        return 1;
    }
    printf("PASS: namespaced caller-defined semaphore prefixes\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    long pid = (long)getpid();
    unsigned int semId = (unsigned int)pid;

    (void)snprintf(gTestShmPath, sizeof(gTestShmPath),
        "/tmp/wolftpm-fwtpm-hal-%ld.shm", pid);
    (void)snprintf(gTestAuxPath, sizeof(gTestAuxPath),
        "/tmp/wolftpm-fwtpm-hal-%ld.aux", pid);
    (void)snprintf(gTestSemCmdBase, sizeof(gTestSemCmdBase),
        "/c%x", semId);
    (void)snprintf(gTestSemRspBase, sizeof(gTestSemRspBase),
        "/r%x", semId);

    failures += ExpectRejected("group-readable", 0640, 0,
        FWTPM_TIS_MAGIC, FWTPM_TIS_VERSION);
    failures += ExpectRejected("world-readable", 0604, 0,
        FWTPM_TIS_MAGIC, FWTPM_TIS_VERSION);
    failures += ExpectRejected("undersized", 0600, -1,
        FWTPM_TIS_MAGIC, FWTPM_TIS_VERSION);
    failures += ExpectRejected("oversized", 0600, 1,
        FWTPM_TIS_MAGIC, FWTPM_TIS_VERSION);
    failures += ExpectRejected("bad magic", 0600, 0,
        FWTPM_TIS_MAGIC ^ 1U, FWTPM_TIS_VERSION);
    failures += ExpectRejected("bad version", 0600, 0,
        FWTPM_TIS_MAGIC, FWTPM_TIS_VERSION + 1U);
    failures += ExpectSymlinkRejected();
    failures += ExpectHardlinkRejected();
    failures += ExpectFifoRejected();
    failures += ExpectSwapRejected();
    failures += ExpectAccepted();
    failures += ExpectDisconnectZeroized();
    failures += TestMetadataValidation();
    failures += TestCustomSemPrefixes();

    CleanupEndpoint();
    printf("fwTPM HAL endpoint tests: %s\n",
        failures == 0 ? "passed" : "failed");
    return failures == 0 ? 0 : 1;
}
