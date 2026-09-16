/* tpm2_tis.c
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

#include <wolftpm/tpm2_tis.h>

/******************************************************************************/
/* --- BEGIN TPM Interface Specification (TIS) Layer */
/******************************************************************************/

enum tpm_tis_access {
    TPM_ACCESS_VALID            = 0x80,
    TPM_ACCESS_ACTIVE_LOCALITY  = 0x20,
    TPM_ACCESS_REQUEST_PENDING  = 0x04,
    TPM_ACCESS_REQUEST_USE      = 0x02,
};

enum tpm_tis_status {
    TPM_STS_VALID               = 0x80,
    TPM_STS_COMMAND_READY       = 0x40,
    TPM_STS_GO                  = 0x20,
    TPM_STS_DATA_AVAIL          = 0x10,
    TPM_STS_DATA_EXPECT         = 0x08,
    TPM_STS_SELF_TEST_DONE      = 0x04,
    TPM_STS_RESP_RETRY          = 0x02,
};

/* enum tpm_tis_int_flags */
#define TPM_GLOBAL_INT_ENABLE       0x80000000UL
#define TPM_INTF_BURST_COUNT_STATIC 0x100
#define TPM_INTF_CMD_READY_INT      0x080
#define TPM_INTF_INT_EDGE_FALLING   0x040
#define TPM_INTF_INT_EDGE_RISING    0x020
#define TPM_INTF_INT_LEVEL_LOW      0x010
#define TPM_INTF_INT_LEVEL_HIGH     0x008
#define TPM_INTF_LOC_CHANGE_INT     0x004
#define TPM_INTF_STS_VALID_INT      0x002
#define TPM_INTF_DATA_AVAIL_INT     0x001


#ifndef TPM_BASE_ADDRESS
#define TPM_BASE_ADDRESS (0xD40000u)
#endif

#ifdef WOLFTPM_I2C
/* For I2C only the lower 8-bits of the address are used */
#define TPM_ACCESS(l)           (TPM_BASE_ADDRESS | 0x0004u | ((l) << 12u))
#define TPM_INTF_CAPS(l)        (TPM_BASE_ADDRESS | 0x0030u | ((l) << 12u))
#define TPM_DID_VID(l)          (TPM_BASE_ADDRESS | 0x0048u | ((l) << 12u))
#define TPM_RID(l)              (TPM_BASE_ADDRESS | 0x004Cu | ((l) << 12u))
#define TPM_I2C_DEVICE_ADDR(l)  (TPM_BASE_ADDRESS | 0x0038u | ((l) << 12u))
#define TPM_DATA_CSUM_ENABLE(l) (TPM_BASE_ADDRESS | 0x0040u | ((l) << 12u))
#define TPM_DATA_CSUM(l)        (TPM_BASE_ADDRESS | 0x0044u | ((l) << 12u))
#else
#define TPM_ACCESS(l)           (TPM_BASE_ADDRESS | 0x0000u | ((l) << 12u))
#define TPM_INTF_CAPS(l)        (TPM_BASE_ADDRESS | 0x0014u | ((l) << 12u))
#define TPM_DID_VID(l)          (TPM_BASE_ADDRESS | 0x0F00u | ((l) << 12u))
#define TPM_RID(l)              (TPM_BASE_ADDRESS | 0x0F04u | ((l) << 12u))
#endif

#define TPM_INT_ENABLE(l)       (TPM_BASE_ADDRESS | 0x0008u | ((l) << 12u))
#define TPM_INT_VECTOR(l)       (TPM_BASE_ADDRESS | 0x000Cu | ((l) << 12u))
#define TPM_INT_STATUS(l)       (TPM_BASE_ADDRESS | 0x0010u | ((l) << 12u))
#define TPM_STS(l)              (TPM_BASE_ADDRESS | 0x0018u | ((l) << 12u))
#define TPM_BURST_COUNT(l)      (TPM_BASE_ADDRESS | 0x0019u | ((l) << 12u))
#define TPM_DATA_FIFO(l)        (TPM_BASE_ADDRESS | TPM_TIS_DATA_FIFO_OFFSET | ((l) << 12u))
#define TPM_XDATA_FIFO(l)       (TPM_BASE_ADDRESS | TPM_TIS_XDATA_FIFO_OFFSET | ((l) << 12u))


/* this option enables named semaphore protection on TIS commands for protected
    concurrent process access */
#ifdef WOLFTPM_TIS_LOCK
    #ifdef __linux__
        #include <semaphore.h>
        #include <fcntl.h>
        #include <sys/stat.h>
        #include <errno.h>
        #include <time.h>

        #define SEM_NAME "/wolftpm"
        #define SEM_PERMS (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
        #define INITIAL_VALUE 1
        #define TIMEOUT_SECONDS 10
        static int gLockCount = 0;

        static int TPM2_TIS_Lock(void)
        {
            int ret = 0;
            sem_t *sem;
            struct timespec timeoutTime;

            if (gLockCount == 0) {
                clock_gettime(CLOCK_REALTIME, &timeoutTime);
                timeoutTime.tv_sec += TIMEOUT_SECONDS;

                /* open semaphore and create if not found */
                sem = sem_open(SEM_NAME, O_CREAT | O_RDWR, SEM_PERMS, INITIAL_VALUE);
                if (sem == SEM_FAILED) {
                #ifdef DEBUG_WOLFTPM
                    printf("TPM2_TIS_Lock: Semaphore %s open failed! %d\n",
                        SEM_NAME, errno);
                #endif
                    return BAD_MUTEX_E;
                }

                /* Try and decrement semaphore */
                if (sem_timedwait(sem, &timeoutTime) != 0) {
                #ifdef DEBUG_WOLFTPM
                    printf("TPM2_TIS_Lock: Semaphore %s timeout! %d\n",
                        SEM_NAME, errno);
                #endif
                    ret = WC_TIMEOUT_E;
                }

                sem_close(sem);
            }
            if (ret == 0) {
                gLockCount++;
            }

            return ret;
        }

        static void TPM2_TIS_Unlock(void)
        {
            if (gLockCount > 0) {
                gLockCount--;
            }
            if (gLockCount == 0) {
                sem_t *sem = sem_open(SEM_NAME, O_RDWR);
                if (sem == SEM_FAILED) {
                #ifdef DEBUG_WOLFTPM
                    printf("TPM2_TIS_Unlock: Semaphore %s open failed! %d\n",
                        SEM_NAME, errno);
                #endif
                    return;
                }

                sem_post(sem); /* increment semaphore */
                sem_close(sem);
            }
        }
        #define TPM2_TIS_LOCK()   TPM2_TIS_Lock()
        #define TPM2_TIS_UNLOCK() TPM2_TIS_Unlock()
    #else
        #error TPM TIS Locking not supported on this platform
    #endif /* __linux__ */
#endif /* WOLFTPM_TIS_LOCK */
#ifndef TPM2_TIS_LOCK
#define TPM2_TIS_LOCK() 0
#endif
#ifndef TPM2_TIS_UNLOCK
#define TPM2_TIS_UNLOCK()
#endif


int TPM2_TIS_Read(TPM2_CTX* ctx, word32 addr, byte* result,
    word32 len)
{
    int rc;
#ifndef WOLFTPM_ADV_IO
    byte txBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
    byte rxBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
#endif

    if (ctx == NULL || result == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    rc = TPM2_TIS_LOCK();
    if (rc != 0)
        return rc;

#ifdef WOLFTPM_ADV_IO
    rc = ctx->ioCb(ctx, TPM_TIS_READ, addr, result, len, ctx->userCtx);
#else
    txBuf[0] = TPM_TIS_READ | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMSET(&txBuf[TPM_TIS_HEADER_SZ], 0, sizeof(txBuf) - TPM_TIS_HEADER_SZ);
    XMEMSET(rxBuf, 0, sizeof(rxBuf));

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + TPM_TIS_HEADER_SZ, ctx->userCtx);

    XMEMCPY(result, &rxBuf[TPM_TIS_HEADER_SZ], len);
    TPM2_ForceZero(txBuf, sizeof(txBuf));
    TPM2_ForceZero(rxBuf, sizeof(rxBuf));
#endif
    TPM2_TIS_UNLOCK();
#ifdef WOLFTPM_DEBUG_IO
    printf("TIS Read addr %x, len %d\n", addr, len);
    TPM2_PrintBin(result, len);
#endif
    return rc;
}

int TPM2_TIS_Write(TPM2_CTX* ctx, word32 addr, const byte* value,
    word32 len)
{
    int rc;
#ifndef WOLFTPM_ADV_IO
    byte txBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
    byte rxBuf[MAX_SPI_FRAMESIZE+TPM_TIS_HEADER_SZ];
#endif

    if (ctx == NULL || value == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    rc = TPM2_TIS_LOCK();
    if (rc != 0)
        return rc;

#ifdef WOLFTPM_ADV_IO
    rc = ctx->ioCb(ctx, TPM_TIS_WRITE, addr, (byte*)value, len, ctx->userCtx);
#else
    txBuf[0] = TPM_TIS_WRITE | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMCPY(&txBuf[TPM_TIS_HEADER_SZ], value, len);
    if (len < MAX_SPI_FRAMESIZE) {
        XMEMSET(&txBuf[TPM_TIS_HEADER_SZ + len], 0,
            sizeof(txBuf) - TPM_TIS_HEADER_SZ - len);
    }
    XMEMSET(rxBuf, 0, sizeof(rxBuf));

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + TPM_TIS_HEADER_SZ, ctx->userCtx);
    TPM2_ForceZero(txBuf, sizeof(txBuf));
    TPM2_ForceZero(rxBuf, sizeof(rxBuf));
#endif
    TPM2_TIS_UNLOCK();
#ifdef WOLFTPM_DEBUG_IO
    printf("TIS write addr %x, len %d\n", addr, len);
    TPM2_PrintBin(value, len);
#endif
    return rc;
}

int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout)
{
    int rc;
    byte access = 0;

    do {
        rc = TPM2_TIS_Read(ctx, TPM_ACCESS(0), &access, sizeof(access));
        /* if chip isn't present MISO will be high and return 0xFF */
        if (rc == TPM_RC_SUCCESS && (access & TPM_ACCESS_VALID) &&
                (access != TPM_TIS_ACCESS_INVALID)) {
            return TPM_RC_SUCCESS;
        }
        XTPM_WAIT();
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);
#ifdef WOLFTPM_DEBUG_TIMEOUT
    printf("TIS_StartupWait: Timeout %d\n", TPM_TIMEOUT_TRIES - timeout);
#endif
    if (timeout <= 0)
        return TPM_RC_TIMEOUT;
    return rc;
}

int TPM2_TIS_CheckLocality(TPM2_CTX* ctx, int locality, byte* access)
{
    return TPM2_TIS_Read(ctx, TPM_ACCESS(locality), access, sizeof(*access));
}

static int TPM2_TIS_CheckLocalityAccessValid(TPM2_CTX* ctx, int locality,
    byte access)
{
    /* Reject a floating/unimplemented locality (see TPM_TIS_ACCESS_INVALID);
     * otherwise e.g. an unsupported locality 4 would look active. */
    if (access != TPM_TIS_ACCESS_INVALID &&
        (access & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
                  (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
        ctx->locality = locality;
        return locality;
    }
    return -1;
}

int TPM2_TIS_RequestLocalityEx(TPM2_CTX* ctx, int locality, int timeout)
{
    int rc;
    byte access = 0;

    rc = TPM2_TIS_CheckLocality(ctx, locality, &access);
    if (rc == TPM_RC_SUCCESS) {
        rc = TPM2_TIS_CheckLocalityAccessValid(ctx, locality, access);
        if (rc >= 0)
            return rc;
    }

    access = TPM_ACCESS_REQUEST_USE;
    rc = TPM2_TIS_Write(ctx, TPM_ACCESS(locality), &access, sizeof(access));
    if (rc == TPM_RC_SUCCESS) {
        do {
            access = 0;
            rc = TPM2_TIS_CheckLocality(ctx, locality, &access);
            if (rc == TPM_RC_SUCCESS) {
                rc = TPM2_TIS_CheckLocalityAccessValid(ctx, locality, access);
                if (rc >= 0)
                    return rc;
            }
            XTPM_WAIT();
        } while (rc < 0 && --timeout > 0);
#ifdef WOLFTPM_DEBUG_TIMEOUT
        printf("TIS_RequestLocality: Timeout %d\n", TPM_TIMEOUT_TRIES - timeout);
#endif
        if (timeout <= 0)
            return TPM_RC_TIMEOUT;
    }

    return rc;
}

int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout)
{
    int rc;
    int locality = WOLFTPM_LOCALITY_DEFAULT;
#ifdef WOLFTPM_TIS_RESET_STALE_LOCALITY
    int l;
    byte access = 0;

    /* Recover a wedge (see WOLFTPM_TIS_RESET_STALE_LOCALITY in tpm2_tis.h): if
     * the default locality is not active, release any other active one so it
     * can be granted instead of spinning to timeout. */
    if (TPM2_TIS_CheckLocality(ctx, locality, &access) == TPM_RC_SUCCESS &&
            (access & TPM_ACCESS_ACTIVE_LOCALITY) == 0) {
        for (l = 0; l <= WOLFTPM_LOCALITY_MAX; l++) {
            if (l == locality) {
                continue;
            }
            access = 0;
            if (TPM2_TIS_CheckLocality(ctx, l, &access) == TPM_RC_SUCCESS &&
                    access != TPM_TIS_ACCESS_INVALID &&
                    (access & TPM_ACCESS_ACTIVE_LOCALITY)) {
                (void)TPM2_TIS_ReleaseLocality(ctx, l);
            }
        }
    }
#endif /* WOLFTPM_TIS_RESET_STALE_LOCALITY */

    rc = TPM2_TIS_RequestLocalityEx(ctx, locality, timeout);
    /* RequestLocalityEx returns the granted locality (0-4) on success; status
     * callers expect TPM_RC_SUCCESS, so map any granted locality onto it. */
    if (rc >= 0 && rc <= WOLFTPM_LOCALITY_MAX)
        rc = TPM_RC_SUCCESS;
    return rc;
}

int TPM2_TIS_ReleaseLocality(TPM2_CTX* ctx, int locality)
{
    /* Relinquish the locality by writing the active locality bit. The TPM
     * clears its active locality so another locality can be requested. */
    byte access = TPM_ACCESS_ACTIVE_LOCALITY;
    return TPM2_TIS_Write(ctx, TPM_ACCESS(locality), &access, sizeof(access));
}

int TPM2_TIS_GetInfo(TPM2_CTX* ctx)
{
    int rc;
    word32 reg;

    rc = TPM2_TIS_Read(ctx, TPM_INTF_CAPS(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc != TPM_RC_SUCCESS)
        return rc;
#ifdef BIG_ENDIAN_ORDER
    reg = ByteReverseWord32(reg);
#endif
    ctx->caps = reg;

    rc = TPM2_TIS_Read(ctx, TPM_DID_VID(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc != TPM_RC_SUCCESS)
        return rc;
#ifdef BIG_ENDIAN_ORDER
    reg = ByteReverseWord32(reg);
#endif
    ctx->did_vid = reg;

    reg = 0;
    rc = TPM2_TIS_Read(ctx, TPM_RID(ctx->locality), (byte*)&reg, 1);
    if (rc != TPM_RC_SUCCESS)
        return rc;
#ifdef BIG_ENDIAN_ORDER
    reg = ByteReverseWord32(reg);
#endif
    ctx->rid = reg;

    return TPM_RC_SUCCESS;
}

int TPM2_TIS_Status(TPM2_CTX* ctx, byte* status)
{
    return TPM2_TIS_Read(ctx, TPM_STS(ctx->locality), status,
        sizeof(*status));
}

/* Budget for the wait loops below. An iteration count makes the real timeout
 * depend on host speed, so a >20 s RSA key generation times out intermittently.
 * Use TPM_TIMEOUT_MS of real time where a monotonic clock exists; elsewhere
 * keep counting exactly as before so no port gains a requirement. */
typedef struct TPM2_TIS_TIMEOUT {
#ifdef WOLFTPM_HAVE_MONOTONIC_MS
    word32 start;
    word32 last;      /* most recent tick that differed from the one before */
    int stagnant;     /* consecutive polls with no clock progress */
#endif
#if defined(DEBUG_WOLFTPM) && !defined(WOLFTPM_NO_STD_HEADERS) && \
    defined(WOLFTPM_HAVE_MONOTONIC_MS)
    #define WOLFTPM_TIS_PROGRESS
    word32 secs;  /* whole seconds already marked with a dot */
#endif
    int tries;
} TPM2_TIS_TIMEOUT;

static void TPM2_TIS_TimeoutStart(TPM2_TIS_TIMEOUT* to)
{
    XMEMSET(to, 0, sizeof(*to));
    to->tries = TPM_TIMEOUT_TRIES;
#ifdef WOLFTPM_HAVE_MONOTONIC_MS
    /* A zero tick is a real timestamp (boot, or the word32 wrapping through
     * 0), so it must not be treated as an unreadable clock. */
    to->start = XTPM_GET_TIMEMS();
    to->last = to->start;
#endif
}

/* Returns 1 once the budget is spent, 0 while there is still time. */
static int TPM2_TIS_TimeoutExpired(TPM2_TIS_TIMEOUT* to)
{
#ifdef WOLFTPM_HAVE_MONOTONIC_MS
    word32 now, elapsed;
#endif

    if (to->tries > 0) {
        to->tries--;
    }
#ifdef WOLFTPM_HAVE_MONOTONIC_MS
    now = XTPM_GET_TIMEMS();
    /* unsigned subtraction stays correct across the word32 wrap */
    elapsed = (word32)(now - to->start);

    /* A wait never legitimately spans hours, so an implausible elapsed means
     * the tick source returned garbage (a failed read yields zero, which the
     * subtraction turns into a huge value). Treat it as no progress rather
     * than expiring on one bad sample. */
    if (elapsed > (word32)(TPM_TIMEOUT_MS) * 10u) {
        now = to->last;
    #ifdef WOLFTPM_TIS_PROGRESS
        elapsed = (word32)(now - to->start);
    #endif
    }
    else if (elapsed >= TPM_TIMEOUT_MS) {
        return 1;
    }

    /* A clock that stops advancing - at startup or part way through - would
     * otherwise never reach the deadline and the wait would hang. Bound it by
     * consecutive polls that saw no progress, independent of the iteration
     * cap, so this holds when TPM_TIMEOUT_TRIES is zero ("no cap") too. */
    if (now == to->last) {
        if (++to->stagnant >= TPM_TIMEOUT_STAGNANT_POLLS) {
            return 1;
        }
    }
    else {
        to->last = now;
        to->stagnant = 0;
    }

#ifdef WOLFTPM_TIS_PROGRESS
    /* Waits of a minute or more are normal for key generation, so show a dot
     * per second rather than let a slow command look like a hang. */
    if (elapsed / 1000u > to->secs) {
        to->secs = elapsed / 1000u;
        printf(".");
        fflush(stdout);
    }
#endif
    return 0;
#else
    return (to->tries <= 0) ? 1 : 0;
#endif
}

#ifdef WOLFTPM_TIS_PROGRESS
/* End the dot line, if any were printed. */
static void TPM2_TIS_TimeoutDone(TPM2_TIS_TIMEOUT* to)
{
    if (to->secs > 0) {
        printf("\n");
        fflush(stdout);
    }
}
#else
    #define TPM2_TIS_TimeoutDone(to) (void)(to)
#endif

#ifdef WOLFTPM_DEBUG_TIMEOUT
/* Elapsed ms where a clock exists, else polls taken. */
static word32 TPM2_TIS_TimeoutSpent(TPM2_TIS_TIMEOUT* to)
{
#ifdef WOLFTPM_HAVE_MONOTONIC_MS
    return (word32)(XTPM_GET_TIMEMS() - to->start);
#else
    return (word32)(TPM_TIMEOUT_TRIES - to->tries);
#endif
}
#endif

int TPM2_TIS_WaitForStatus(TPM2_CTX* ctx, byte status, byte status_mask)
{
    int rc;
    int expired = 0;
    TPM2_TIS_TIMEOUT to;
    byte reg = 0;

    TPM2_TIS_TimeoutStart(&to);
    do {
        rc = TPM2_TIS_Status(ctx, &reg);
        if (rc == TPM_RC_SUCCESS && (reg & status) == status_mask)
            break;
        XTPM_WAIT();
        expired = TPM2_TIS_TimeoutExpired(&to);
    } while (rc == TPM_RC_SUCCESS && !expired);
    TPM2_TIS_TimeoutDone(&to);
#ifdef WOLFTPM_DEBUG_TIMEOUT
    printf("TIS_WaitForStatus: spent %u\n",
        (unsigned int)TPM2_TIS_TimeoutSpent(&to));
#endif
    if (expired)
        return TPM_RC_TIMEOUT;
    return rc;
}

int TPM2_TIS_Ready(TPM2_CTX* ctx)
{
    byte status = TPM_STS_COMMAND_READY;
    return TPM2_TIS_Write(ctx, TPM_STS(ctx->locality), &status, sizeof(status));
}

int TPM2_TIS_GetBurstCount(TPM2_CTX* ctx, word16* burstCount)
{
    int rc = TPM_RC_SUCCESS;

    if (burstCount == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    if (TPM2_GetVendorID() == TPM_VENDOR_STM) {
        *burstCount = 32; /* fixed value */
    }
    else
#endif

    {
        int expired = 0;
        TPM2_TIS_TIMEOUT to;

        TPM2_TIS_TimeoutStart(&to);
        *burstCount = 0;
        do {
            rc = TPM2_TIS_Read(ctx, TPM_BURST_COUNT(ctx->locality),
                (byte*)burstCount, sizeof(*burstCount));
        #ifdef BIG_ENDIAN_ORDER
            *burstCount = ByteReverseWord16(*burstCount);
        #endif
            if (rc == TPM_RC_SUCCESS && *burstCount > 0)
                break;
            XTPM_WAIT();
            expired = TPM2_TIS_TimeoutExpired(&to);
        } while (rc == TPM_RC_SUCCESS && !expired);
        TPM2_TIS_TimeoutDone(&to);

    #ifdef WOLFTPM_DEBUG_TIMEOUT
        printf("TIS_GetBurstCount: spent %u\n",
            (unsigned int)TPM2_TIS_TimeoutSpent(&to));
    #endif

        if (*burstCount > MAX_SPI_FRAMESIZE)
            *burstCount = MAX_SPI_FRAMESIZE;

        if (expired)
            return TPM_RC_TIMEOUT;
    }

    return rc;
}

/* Validate a TPM-reported response size from the wire header against the
 * caller buffer before the receive loop writes into it. */
int TPM2_TIS_ValidateRspSz(int rspSz, int packetSize)
{
    int rc = TPM_RC_SUCCESS;
    if (rspSz < TPM2_HEADER_SIZE || rspSz > MAX_RESPONSE_SIZE ||
            rspSz > packetSize) {
        rc = TPM_RC_FAILURE;
    }
    return rc;
}

int TPM2_TIS_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc;
    int xferSz, pos, rspSz;
    byte access, status = 0;
    word16 burstCount;

    rc = TPM2_TIS_LOCK();
    if (rc != 0)
        return rc;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    /* Make sure TPM is ready for command */
    rc = TPM2_TIS_Status(ctx, &status);
    if (rc != TPM_RC_SUCCESS)
        goto exit;
    if ((status & TPM_STS_COMMAND_READY) == 0) {
        /* Tell TPM chip to expect a command */
        rc = TPM2_TIS_Ready(ctx);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        /* Wait for command ready (TPM_STS_COMMAND_READY = 1) */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_COMMAND_READY,
                                         TPM_STS_COMMAND_READY);
        if (rc != TPM_RC_SUCCESS)
            goto exit;
    }

    /* Write Command */
    pos = 0;
    while (pos < packet->pos) {
        rc = TPM2_TIS_GetBurstCount(ctx, &burstCount);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        xferSz = packet->pos - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_Write(ctx, TPM_DATA_FIFO(ctx->locality), &packet->buf[pos],
                               xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;
        pos += xferSz;

        if (pos < packet->pos) {
            /* Wait for expect more data (TPM_STS_DATA_EXPECT = 1) */
            rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT,
                                             TPM_STS_DATA_EXPECT);
            if (rc != TPM_RC_SUCCESS) {
            #ifdef DEBUG_WOLFTPM
                printf("TPM2_TIS_SendCommand write expected more data!\n");
            #endif
                goto exit;
            }
        }
    }

#if defined(WOLFTPM_ST33) || defined(WOLFTPM_AUTODETECT)
    if (TPM2_GetVendorID() != TPM_VENDOR_STM)
#endif
    {
        /* Wait for TPM_STS_DATA_EXPECT = 0 and TPM_STS_VALID = 1 */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT | TPM_STS_VALID,
                                        TPM_STS_VALID);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_TIS_SendCommand status valid timeout!\n");
        #endif
            goto exit;
        }
    }

    /* Execute Command */
    access = TPM_STS_GO;
    rc = TPM2_TIS_Write(ctx, TPM_STS(ctx->locality), &access,
                           sizeof(access));
    if (rc != TPM_RC_SUCCESS)
        goto exit;

    /* Read response */
    pos = 0;
    rspSz = TPM2_HEADER_SIZE; /* Read at least TPM header */
    while (pos < rspSz) {
        /* Wait for data to be available (TPM_STS_DATA_AVAIL = 1) */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_AVAIL,
                                         TPM_STS_DATA_AVAIL);
        if (rc != TPM_RC_SUCCESS) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_TIS_SendCommand read no data available!\n");
        #endif
            goto exit;
        }

        rc = TPM2_TIS_GetBurstCount(ctx, &burstCount);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        xferSz = rspSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_Read(ctx, TPM_DATA_FIFO(ctx->locality), &packet->buf[pos],
                              xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        pos += xferSz;

        /* Get real response size */
        if (pos == TPM2_HEADER_SIZE) {
            /* Extract size from header */
            UINT32 tmpSz;
            XMEMCPY(&tmpSz, &packet->buf[2], sizeof(UINT32));
            rspSz = TPM2_Packet_SwapU32(tmpSz);

            /* safety check for stuck FFFF case */
            rc = TPM2_TIS_ValidateRspSz(rspSz, packet->size);
            if (rc != TPM_RC_SUCCESS) {
                goto exit;
            }
        }
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response: %d\n", rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    rc = TPM_RC_SUCCESS;

exit:

    /* Tell TPM we are done */
    if (rc == TPM_RC_SUCCESS)
        rc = TPM2_TIS_Ready(ctx);

    TPM2_TIS_UNLOCK();

    return rc;
}

/******************************************************************************/
/* --- END TPM Interface Layer -- */
/******************************************************************************/
