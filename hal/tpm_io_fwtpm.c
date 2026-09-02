/* tpm_io_fwtpm.c
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

/* Client-side HAL for connecting to fwTPM via TIS/shared memory.
 *
 * This implements the TPM2_IoCb (ADV_IO mode) callback that translates
 * TIS register reads/writes from tpm2_tis.c into shared memory
 * operations signaled by POSIX semaphores.
 *
 * Included from hal/tpm_io.c via #include when WOLFTPM_FWTPM_HAL is defined.
 */

#ifdef WOLFTPM_INCLUDE_IO_FILE

#include <wolftpm/fwtpm/fwtpm_tis.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <semaphore.h>

/* Static client context (one connection per process).
 * By design, only one fwTPM server instance is connected per process.
 * This callback does not synchronize access to the client context; callers
 * must serialize concurrent initialization and use. */
static FWTPM_TIS_CLIENT_CTX gFwtpmClient;
static int gFwtpmClientInit = 0;

static int FWTPM_TIS_ClientLock(int fd)
{
    int rc;

    do {
        rc = flock(fd, LOCK_EX);
    } while (rc != 0 && errno == EINTR);

    return rc;
}

static int FWTPM_TIS_ClientTryLock(int fd)
{
    return flock(fd, LOCK_EX | LOCK_NB);
}

static void FWTPM_TIS_ClientUnlock(int fd)
{
    int rc;

    do {
        rc = flock(fd, LOCK_UN);
    } while (rc != 0 && errno == EINTR);
}

static int FWTPM_TIS_ServerActive(const FWTPM_TIS_REGS* shm)
{
    return FWTPM_TIS_ATOMIC_LOAD(shm->magic) == FWTPM_TIS_MAGIC;
}

static int FWTPM_TIS_ClientValidateShm(const struct stat* st)
{
    mode_t expectedMode = S_IRUSR | S_IWUSR;

    if (!S_ISREG(st->st_mode) || st->st_uid != geteuid() ||
            st->st_nlink != 1 ||
            (st->st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != expectedMode ||
            st->st_size != (off_t)sizeof(FWTPM_TIS_REGS)) {
        return TPM_RC_FAILURE;
    }
    return TPM_RC_SUCCESS;
}

int FWTPM_TIS_ClientConnect(FWTPM_TIS_CLIENT_CTX* client)
{
    int fd;
    int openFlags;
    int fdFlags = 0;
    UINT32 magic;
    struct stat st;
    struct stat pathSt;
    FWTPM_TIS_REGS* shm;
    sem_t* semCmd;
    sem_t* semRsp;

    if (client == NULL) {
        return BAD_FUNC_ARG;
    }

    XMEMSET(client, 0, sizeof(FWTPM_TIS_CLIENT_CTX));
    client->shmFd = -1;

    /* Open existing shared memory file. O_NOFOLLOW and O_CLOEXEC are not
     * universally available across POSIX targets — guard at compile time
     * and fall back to lstat/inode checks and fcntl(FD_CLOEXEC). O_NONBLOCK
     * prevents a substituted FIFO from blocking before fstat rejects it. */
    openFlags = O_RDWR;
#ifdef O_NOFOLLOW
    openFlags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    openFlags |= O_CLOEXEC;
#endif
#ifdef O_NONBLOCK
    openFlags |= O_NONBLOCK;
#endif
    if (lstat(FWTPM_TIS_SHM_PATH, &pathSt) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: lstat(%s) failed: %d (%s)\n",
            FWTPM_TIS_SHM_PATH, errno, strerror(errno));
    #endif
        return TPM_RC_FAILURE;
    }
    if (!S_ISREG(pathSt.st_mode)) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: %s is not a regular file\n",
            FWTPM_TIS_SHM_PATH);
    #endif
        return TPM_RC_FAILURE;
    }
    fd = open(FWTPM_TIS_SHM_PATH, openFlags);
    if (fd < 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: open(%s) failed: %d (%s)\n",
            FWTPM_TIS_SHM_PATH, errno, strerror(errno));
    #endif
        return TPM_RC_FAILURE;
    }
#ifndef O_CLOEXEC
    fdFlags = fcntl(fd, F_GETFD);
    if (fdFlags >= 0) {
        (void)fcntl(fd, F_SETFD, fdFlags | FD_CLOEXEC);
    }
#elif !defined(O_NONBLOCK)
    (void)fdFlags;
#endif

    /* Authenticate the data-bearing endpoint before mapping it. Named
     * semaphores carry wakeups only and are derived from this validated file
     * owner below. */
    if (fstat(fd, &st) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: fstat(%s) failed: %d (%s)\n",
            FWTPM_TIS_SHM_PATH, errno, strerror(errno));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }
    /* Check this ahead of the shared validator so a size mismatch gets the
     * specific client/server rebuild diagnostic. */
    if (st.st_size != (off_t)sizeof(FWTPM_TIS_REGS)) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: endpoint is %llu bytes; this build expects %llu "
               "(rebuild client and server with matching options)\n",
            (unsigned long long)st.st_size,
            (unsigned long long)sizeof(FWTPM_TIS_REGS));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }
    if (FWTPM_TIS_ClientValidateShm(&st) != TPM_RC_SUCCESS ||
            st.st_dev != pathSt.st_dev || st.st_ino != pathSt.st_ino) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: untrusted shm metadata (expected %lu bytes, "
               "mode 0600, uid %lu)\n",
            (unsigned long)sizeof(FWTPM_TIS_REGS),
            (unsigned long)geteuid());
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }
#ifdef O_NONBLOCK
    fdFlags = fcntl(fd, F_GETFL);
    if (fdFlags < 0 ||
            fcntl(fd, F_SETFL, fdFlags & ~O_NONBLOCK) != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: failed to clear O_NONBLOCK\n");
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }
#endif

    shm = (FWTPM_TIS_REGS*)mmap(NULL, sizeof(FWTPM_TIS_REGS),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm == MAP_FAILED) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: mmap failed: %d (%s)\n", errno, strerror(errno));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Acquire the validity sentinel before reading the published header. */
    magic = FWTPM_TIS_ATOMIC_LOAD(shm->magic);
    if (magic != FWTPM_TIS_MAGIC ||
            shm->version != FWTPM_TIS_VERSION) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: bad header magic=0x%08x version=%u\n",
            (unsigned int)magic, (unsigned int)shm->version);
    #endif
        munmap(shm, sizeof(FWTPM_TIS_REGS));
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Open existing semaphores (server creates them) */
    semCmd = sem_open(FWTPM_TIS_SEM_CMD, 0);
    if (semCmd == SEM_FAILED) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: sem_open(%s) failed: %d (%s)\n",
            FWTPM_TIS_SEM_CMD, errno, strerror(errno));
    #endif
        munmap(shm, sizeof(FWTPM_TIS_REGS));
        close(fd);
        return TPM_RC_FAILURE;
    }

    semRsp = sem_open(FWTPM_TIS_SEM_RSP, 0);
    if (semRsp == SEM_FAILED) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: sem_open(%s) failed: %d (%s)\n",
            FWTPM_TIS_SEM_RSP, errno, strerror(errno));
    #endif
        sem_close(semCmd);
        munmap(shm, sizeof(FWTPM_TIS_REGS));
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Reject a replaced pathname or metadata change after opening the
     * per-owner semaphore pair. */
    if (fstat(fd, &st) != 0 ||
            FWTPM_TIS_ClientValidateShm(&st) != TPM_RC_SUCCESS ||
            lstat(FWTPM_TIS_SHM_PATH, &pathSt) != 0 ||
            !S_ISREG(pathSt.st_mode) || st.st_dev != pathSt.st_dev ||
            st.st_ino != pathSt.st_ino) {
        sem_close(semRsp);
        sem_close(semCmd);
        munmap(shm, sizeof(FWTPM_TIS_REGS));
        close(fd);
        return TPM_RC_FAILURE;
    }

    client->shm = shm;
    client->shmFd = fd;
    client->semCmd = semCmd;
    client->semRsp = semRsp;

#ifdef DEBUG_WOLFTPM
    printf("fwTPM HAL: Connected to %s\n", FWTPM_TIS_SHM_PATH);
#endif

    return TPM_RC_SUCCESS;
}

void FWTPM_TIS_ClientDisconnect(FWTPM_TIS_CLIENT_CTX* client)
{
    if (client == NULL) {
        return;
    }

    if (client->semRsp != NULL) {
        sem_close((sem_t*)client->semRsp);
        client->semRsp = NULL;
    }
    if (client->semCmd != NULL) {
        sem_close((sem_t*)client->semCmd);
        client->semCmd = NULL;
    }
    if (client->shm != NULL) {
        if (client->shmFd >= 0 &&
                FWTPM_TIS_ClientTryLock(client->shmFd) == 0) {
            TPM2_ForceZero(client->shm->reg_data,
                sizeof(client->shm->reg_data));
            FWTPM_TIS_ClientUnlock(client->shmFd);
        }
        munmap(client->shm, sizeof(FWTPM_TIS_REGS));
        client->shm = NULL;
    }
    if (client->shmFd >= 0) {
        close(client->shmFd);
        client->shmFd = -1;
    }
}

static void FWTPM_TIS_ClientCleanup(void)
{
    if (gFwtpmClientInit) {
        FWTPM_TIS_ClientDisconnect(&gFwtpmClient);
        gFwtpmClientInit = 0;
    }
}

/* TPM2_IoCb implementation for fwTPM TIS/shm (ADV_IO mode) */
int TPM2_IoCb_FwTPM(TPM2_CTX* ctx, int isRead, word32 addr,
    byte* buf, word16 size, void* userCtx)
{
    FWTPM_TIS_CLIENT_CTX* client = &gFwtpmClient;
    FWTPM_TIS_REGS* shm;

    (void)ctx;
    (void)userCtx;

    /* Lazy connect on first call. Callers must serialize this path. */
    if (!gFwtpmClientInit) {
        static int atexitRegistered = 0;
        int rc = FWTPM_TIS_ClientConnect(client);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
        gFwtpmClientInit = 1;
        if (!atexitRegistered) {
            atexit(FWTPM_TIS_ClientCleanup);
            atexitRegistered = 1;
        }
    }

    shm = client->shm;
    if (shm == NULL) {
        return TPM_RC_FAILURE;
    }

    /* Reject transfers larger than the reg_data buffer */
    if (size > (word16)sizeof(shm->reg_data)) {
        return BAD_FUNC_ARG;
    }

    /* Serialize the complete shared request slot lifecycle across clients. */
    if (FWTPM_TIS_ClientLock(client->shmFd) != 0) {
        return TPM_RC_FAILURE;
    }
    if (!FWTPM_TIS_ServerActive(shm)) {
        FWTPM_TIS_ClientUnlock(client->shmFd);
        return TPM_RC_FAILURE;
    }

    /* Fill register access request */
    shm->reg_addr = addr;
    shm->reg_len = size;
    shm->reg_is_write = isRead ? 0 : 1;

    if (!isRead) {
        XMEMCPY(shm->reg_data, buf, size);
    }

    /* Signal server and wait for completion */
    if (sem_post((sem_t*)client->semCmd) != 0) {
        TPM2_ForceZero(shm->reg_data, sizeof(shm->reg_data));
        FWTPM_TIS_ClientUnlock(client->shmFd);
        return TPM_RC_FAILURE;
    }
    while (sem_wait((sem_t*)client->semRsp) != 0) {
        if (errno != EINTR) {
            TPM2_ForceZero(shm->reg_data, sizeof(shm->reg_data));
            FWTPM_TIS_ClientUnlock(client->shmFd);
            return TPM_RC_FAILURE;
        }
    }
    if (!FWTPM_TIS_ServerActive(shm)) {
        TPM2_ForceZero(shm->reg_data, sizeof(shm->reg_data));
        FWTPM_TIS_ClientUnlock(client->shmFd);
        return TPM_RC_FAILURE;
    }

    /* Copy result for reads */
    if (isRead) {
        XMEMCPY(buf, shm->reg_data, size);
    }
    if (!FWTPM_TIS_ServerActive(shm)) {
        if (isRead) {
            TPM2_ForceZero(buf, size);
        }
        TPM2_ForceZero(shm->reg_data, sizeof(shm->reg_data));
        FWTPM_TIS_ClientUnlock(client->shmFd);
        return TPM_RC_FAILURE;
    }
    TPM2_ForceZero(shm->reg_data, sizeof(shm->reg_data));
    FWTPM_TIS_ClientUnlock(client->shmFd);

    return TPM_RC_SUCCESS;
}

#endif /* WOLFTPM_INCLUDE_IO_FILE */
