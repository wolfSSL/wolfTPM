/* fwtpm_tis_shm.c
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

/* fwTPM TIS POSIX Shared Memory Transport
 *
 * Default TIS transport for desktop/testing. Uses a file-backed shared
 * memory region and POSIX named semaphores for client-server signaling.
 *
 * Client: hal/tpm_io_fwtpm.c (opens the same shm/semaphores)
 * Server: This file provides FWTPM_TIS_HAL callbacks for fwtpm_tis.c
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#if defined(WOLFTPM_FWTPM) && defined(WOLFTPM_FWTPM_TIS)

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_tis.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#include <sys/stat.h>
#endif

#include <sys/mman.h>
#include <semaphore.h>

/* Internal context for POSIX shm transport */
typedef struct {
    FWTPM_TIS_REGS* regs;      /* mmap pointer */
    int shmFd;                  /* shm file descriptor */
    sem_t* semCmd;              /* command semaphore */
    sem_t* semRsp;              /* response semaphore */
    char semCmdName[FWTPM_TIS_SEM_NAME_SIZE];
    char semRspName[FWTPM_TIS_SEM_NAME_SIZE];
} FWTPM_TIS_SHM_CTX;

/* Single server per process */
static FWTPM_TIS_SHM_CTX gTisShmCtx;

static void TisShmUnlinkOldEndpoint(const char* semCmdName,
    const char* semRspName)
{
    (void)sem_unlink(semCmdName);
    (void)sem_unlink(semRspName);
}

/* Per-UID names keep concurrent users' wakeup semaphores apart. */
static int TisShmMakeSemNames(uid_t ownerUid, char* semCmd, size_t semCmdSz,
    char* semRsp, size_t semRspSz)
{
    int cmdLen;
    int rspLen;

    cmdLen = XSNPRINTF(semCmd, semCmdSz, "%s-%lu", FWTPM_TIS_SEM_CMD,
        (unsigned long)ownerUid);
    rspLen = XSNPRINTF(semRsp, semRspSz, "%s-%lu", FWTPM_TIS_SEM_RSP,
        (unsigned long)ownerUid);
    if (cmdLen <= 0 || (size_t)cmdLen >= semCmdSz ||
            rspLen <= 0 || (size_t)rspLen >= semRspSz) {
        return -1;
    }
    return 0;
}

/* --- HAL Callbacks --- */

static int TisShmInit(void* ctx, FWTPM_TIS_REGS** regs)
{
    FWTPM_TIS_SHM_CTX* shm = (FWTPM_TIS_SHM_CTX*)ctx;
    int fd;
    struct stat shmStat;
    /* Threat model: fwtpm_server is a dev/test tool and is NOT intended to
     * run setuid or as a privileged daemon. O_NOFOLLOW + mode 0600 is
     * sufficient for non-privileged execution. */
    int openFlags = O_CREAT | O_EXCL | O_RDWR;

#ifdef O_NOFOLLOW
    openFlags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    openFlags |= O_CLOEXEC;
#endif

    shm->regs = NULL;
    shm->shmFd = -1;
    shm->semCmd = NULL;
    shm->semRsp = NULL;
    shm->semCmdName[0] = '\0';
    shm->semRspName[0] = '\0';

    /* Use a fresh inode so locks from a crashed server generation do not
     * prevent new clients from connecting to the replacement server. */
    if (unlink(FWTPM_TIS_SHM_PATH) != 0 && errno != ENOENT) {
        fprintf(stderr, "fwTPM TIS: unlink(%s) failed: %d (%s)\n",
            FWTPM_TIS_SHM_PATH, errno, strerror(errno));
        return -1;
    }
    /* Create shared memory file */
    fd = open(FWTPM_TIS_SHM_PATH, openFlags, 0600);
    if (fd < 0) {
        fprintf(stderr, "fwTPM TIS: open(%s) failed: %d (%s)\n",
            FWTPM_TIS_SHM_PATH, errno, strerror(errno));
        return -1;
    }

    /* Require our own UID and force 0600 on the newly created endpoint. */
    if (fstat(fd, &shmStat) != 0 || !S_ISREG(shmStat.st_mode) ||
            shmStat.st_uid != geteuid() || shmStat.st_nlink != 1 ||
            fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        fprintf(stderr, "fwTPM TIS: shm ownership/permission check failed\n");
        close(fd);
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }

    if (ftruncate(fd, (off_t)sizeof(FWTPM_TIS_REGS)) < 0) {
        fprintf(stderr, "fwTPM TIS: ftruncate failed: %d (%s)\n",
            errno, strerror(errno));
        close(fd);
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }

    if (fstat(fd, &shmStat) != 0 ||
            shmStat.st_size != (off_t)sizeof(FWTPM_TIS_REGS) ||
            (shmStat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) !=
                (S_IRUSR | S_IWUSR)) {
        fprintf(stderr, "fwTPM TIS: invalid shm endpoint metadata\n");
        close(fd);
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }
    if (TisShmMakeSemNames(shmStat.st_uid,
            shm->semCmdName, sizeof(shm->semCmdName),
            shm->semRspName, sizeof(shm->semRspName)) != 0) {
        fprintf(stderr, "fwTPM TIS: failed to derive semaphore names\n");
        close(fd);
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }

    shm->regs = (FWTPM_TIS_REGS*)mmap(NULL, sizeof(FWTPM_TIS_REGS),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm->regs == MAP_FAILED) {
        fprintf(stderr, "fwTPM TIS: mmap failed: %d (%s)\n",
            errno, strerror(errno));
        shm->regs = NULL;
        close(fd);
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }
    shm->shmFd = fd;

    /* Remove stale names only after the data endpoint is ready, immediately
     * before O_EXCL recreates them. Early startup failures therefore leave a
     * still-running server generation's semaphore names intact. */
    TisShmUnlinkOldEndpoint(shm->semCmdName, shm->semRspName);
    shm->semCmd = sem_open(shm->semCmdName, O_CREAT | O_EXCL, 0600, 0);
    if (shm->semCmd == SEM_FAILED) {
        fprintf(stderr, "fwTPM TIS: sem_open(%s) failed: %d (%s)\n",
            shm->semCmdName, errno, strerror(errno));
        shm->semCmd = NULL;
        munmap(shm->regs, sizeof(FWTPM_TIS_REGS));
        shm->regs = NULL;
        close(fd);
        shm->shmFd = -1;
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }

    shm->semRsp = sem_open(shm->semRspName, O_CREAT | O_EXCL, 0600, 0);
    if (shm->semRsp == SEM_FAILED) {
        fprintf(stderr, "fwTPM TIS: sem_open(%s) failed: %d (%s)\n",
            shm->semRspName, errno, strerror(errno));
        sem_close(shm->semCmd);
        sem_unlink(shm->semCmdName);
        shm->semCmd = NULL;
        shm->semRsp = NULL;
        munmap(shm->regs, sizeof(FWTPM_TIS_REGS));
        shm->regs = NULL;
        close(fd);
        shm->shmFd = -1;
        (void)unlink(FWTPM_TIS_SHM_PATH);
        return -1;
    }

    *regs = shm->regs;

    printf("fwTPM TIS: Shared memory at %s (%zu bytes)\n",
        FWTPM_TIS_SHM_PATH, sizeof(FWTPM_TIS_REGS));
    printf("fwTPM TIS: Semaphores: cmd=%s, rsp=%s\n",
        shm->semCmdName, shm->semRspName);

    return 0;
}

static int TisShmWaitRequest(void* ctx)
{
    FWTPM_TIS_SHM_CTX* shm = (FWTPM_TIS_SHM_CTX*)ctx;

    if (sem_wait(shm->semCmd) != 0) {
        if (errno == EINTR) {
            return -1; /* caller should continue loop */
        }
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM TIS: sem_wait error %d (%s)\n",
            errno, strerror(errno));
    #endif
        return -2; /* fatal error */
    }
    return 0;
}

static int TisShmSignalResponse(void* ctx)
{
    FWTPM_TIS_SHM_CTX* shm = (FWTPM_TIS_SHM_CTX*)ctx;
    if (sem_post(shm->semRsp) != 0) {
        return TPM_RC_FAILURE;
    }
    return 0;
}

static void TisShmCleanup(void* ctx)
{
    FWTPM_TIS_SHM_CTX* shm = (FWTPM_TIS_SHM_CTX*)ctx;

    if (shm->regs != NULL) {
        FWTPM_TIS_ATOMIC_STORE(shm->regs->magic, 0U);
        TPM2_ForceZero(shm->regs->reg_data,
            sizeof(shm->regs->reg_data));
        if (shm->semRsp != NULL && shm->semRsp != SEM_FAILED) {
            (void)sem_post(shm->semRsp);
        }
    }
    if (shm->semRsp != NULL && shm->semRsp != SEM_FAILED) {
        sem_close(shm->semRsp);
        if (shm->semRspName[0] != '\0') {
            sem_unlink(shm->semRspName);
        }
        shm->semRsp = NULL;
    }
    if (shm->semCmd != NULL && shm->semCmd != SEM_FAILED) {
        sem_close(shm->semCmd);
        if (shm->semCmdName[0] != '\0') {
            sem_unlink(shm->semCmdName);
        }
        shm->semCmd = NULL;
    }
    if (shm->regs != NULL) {
        munmap(shm->regs, sizeof(FWTPM_TIS_REGS));
        shm->regs = NULL;
    }
    if (shm->shmFd >= 0) {
        close(shm->shmFd);
        unlink(FWTPM_TIS_SHM_PATH);
        shm->shmFd = -1;
    }
}

/* --- Public API --- */

void FWTPM_TIS_SetDefaultHAL(FWTPM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    XMEMSET(&gTisShmCtx, 0, sizeof(gTisShmCtx));
    gTisShmCtx.shmFd = -1;

    ctx->tisHal.init = TisShmInit;
    ctx->tisHal.wait_request = TisShmWaitRequest;
    ctx->tisHal.signal_response = TisShmSignalResponse;
    ctx->tisHal.cleanup = TisShmCleanup;
    ctx->tisHal.ctx = &gTisShmCtx;
}

#endif /* WOLFTPM_FWTPM && WOLFTPM_FWTPM_TIS */
