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
#include <sys/stat.h>
#include <semaphore.h>

/* Static client context (one connection per process).
 * By design, only one fwTPM server instance is connected per process.
 * Thread safety is provided by TPM2_AcquireLock in tpm2_tis.c. */
static FWTPM_TIS_CLIENT_CTX gFwtpmClient;
static int gFwtpmClientInit = 0;

int FWTPM_TIS_ClientConnect(FWTPM_TIS_CLIENT_CTX* client)
{
    int fd;
    int openFlags;
    int fdFlags;
    struct stat st;
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
     * and fall back to fcntl(FD_CLOEXEC) for the close-on-exec semantics. */
    openFlags = O_RDWR;
#ifdef O_NOFOLLOW
    openFlags |= O_NOFOLLOW;
#endif
#ifdef O_CLOEXEC
    openFlags |= O_CLOEXEC;
#endif
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
#else
    (void)fdFlags;
#endif

    /* Verify file is large enough before mapping */
    if (fstat(fd, &st) != 0 ||
            st.st_size < (off_t)sizeof(FWTPM_TIS_REGS)) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: shm file too small (expected %lu)\n",
            (unsigned long)sizeof(FWTPM_TIS_REGS));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }

    shm = (FWTPM_TIS_REGS*)mmap(NULL, sizeof(FWTPM_TIS_REGS),
        PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (shm == MAP_FAILED) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: mmap failed: %d (%s)\n", errno, strerror(errno));
    #endif
        close(fd);
        return TPM_RC_FAILURE;
    }

    /* Validate magic */
    if (shm->magic != FWTPM_TIS_MAGIC) {
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM HAL: bad magic 0x%08x (expected 0x%08x)\n",
            (unsigned int)shm->magic, (unsigned int)FWTPM_TIS_MAGIC);
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

    /* Lazy connect on first call.
     * Note: thread safety is provided by the TPM context lock in tpm2_tis.c
     * (TPM2_AcquireLock), so no additional mutex is needed here. */
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

    /* Fill register access request */
    shm->reg_addr = addr;
    shm->reg_len = size;
    shm->reg_is_write = isRead ? 0 : 1;

    if (!isRead) {
        XMEMCPY(shm->reg_data, buf, size);
    }

    /* Signal server and wait for completion */
    if (sem_post((sem_t*)client->semCmd) != 0) {
        return TPM_RC_FAILURE;
    }
    while (sem_wait((sem_t*)client->semRsp) != 0) {
        if (errno != EINTR) {
            return TPM_RC_FAILURE;
        }
    }

    /* Copy result for reads */
    if (isRead) {
        XMEMCPY(buf, shm->reg_data, size);
    }

    return TPM_RC_SUCCESS;
}

#endif /* WOLFTPM_INCLUDE_IO_FILE */
