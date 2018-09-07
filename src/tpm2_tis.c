/* tpm2_tis.c
 *
 * Copyright (C) 2006-2018 wolfSSL Inc.
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

enum tpm_tis_int_flags {
    TPM_GLOBAL_INT_ENABLE       = 0x80000000,
    TPM_INTF_BURST_COUNT_STATIC = 0x100,
    TPM_INTF_CMD_READY_INT      = 0x080,
    TPM_INTF_INT_EDGE_FALLING   = 0x040,
    TPM_INTF_INT_EDGE_RISING    = 0x020,
    TPM_INTF_INT_LEVEL_LOW      = 0x010,
    TPM_INTF_INT_LEVEL_HIGH     = 0x008,
    TPM_INTF_LOC_CHANGE_INT     = 0x004,
    TPM_INTF_STS_VALID_INT      = 0x002,
    TPM_INTF_DATA_AVAIL_INT     = 0x001,
};


#define TPM_BASE_ADDRESS (0xD40000u)

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
#define TPM_DATA_FIFO(l)        (TPM_BASE_ADDRESS | 0x0024u | ((l) << 12u))
#define TPM_XDATA_FIFO(l)       (TPM_BASE_ADDRESS | 0x0083u | ((l) << 12u))



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

#ifdef WOLFTPM_ADV_IO
    rc = ctx->ioCb(ctx, TPM_TIS_READ, addr, result, len, ctx->userCtx);
#else
    txBuf[0] = TPM_TIS_READ | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    txBuf[4] = 0x00;
    XMEMSET(&txBuf[TPM_TIS_HEADER_SZ], 0, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + TPM_TIS_HEADER_SZ, ctx->userCtx);

    XMEMCPY(result, &rxBuf[TPM_TIS_HEADER_SZ], len);
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

#ifdef WOLFTPM_ADV_IO
    rc = ctx->ioCb(ctx, TPM_TIS_WRITE, addr, (byte*)value, len, ctx->userCtx);
#else
    txBuf[0] = TPM_TIS_WRITE | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    txBuf[4] = 0x00;
    XMEMCPY(&txBuf[TPM_TIS_HEADER_SZ], value, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + TPM_TIS_HEADER_SZ, ctx->userCtx);
#endif
    return rc;
}

int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout)
{
    int rc;
    byte access = 0;

    do {
        rc = TPM2_TIS_Read(ctx, TPM_ACCESS(0), &access, sizeof(access));
        if (rc == TPM_RC_SUCCESS && (access & TPM_ACCESS_VALID))
            return TPM_RC_SUCCESS;
        XTPM_WAIT();
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);
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
    if ((access & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
                  (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
        ctx->locality = locality;
        return locality;
    }
    return -1;
}

int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout)
{
    int rc;
    int locality = WOLFTPM_LOCALITY_DEFAULT;
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
        if (timeout <= 0)
            return TPM_RC_TIMEOUT;
    }

    return rc;
}

int TPM2_TIS_GetInfo(TPM2_CTX* ctx)
{
    int rc;
    word32 reg;

    rc = TPM2_TIS_Read(ctx, TPM_INTF_CAPS(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->caps = reg;
    }

    rc = TPM2_TIS_Read(ctx, TPM_DID_VID(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->did_vid = reg;
    }

    reg = 0;
    rc = TPM2_TIS_Read(ctx, TPM_RID(ctx->locality), (byte*)&reg, 1);
    if (rc == TPM_RC_SUCCESS) {
        ctx->rid = reg;
    }

    return rc;
}

int TPM2_TIS_Status(TPM2_CTX* ctx, byte* status)
{
    return TPM2_TIS_Read(ctx, TPM_STS(ctx->locality), status,
        sizeof(*status));
}

int TPM2_TIS_WaitForStatus(TPM2_CTX* ctx, byte status, byte status_mask)
{
    int rc;
    int timeout = TPM_TIMEOUT_TRIES;
    byte reg = 0;

    do {
        rc = TPM2_TIS_Status(ctx, &reg);
        if (rc == TPM_RC_SUCCESS && (reg & status) == status_mask)
            break;
        XTPM_WAIT();
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);
    if (timeout <= 0)
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
#ifndef WOLFTPM_ST33
    int timeout = TPM_TIMEOUT_TRIES;
#endif

    if (burstCount == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFTPM_ST33
    *burstCount = 32; /* fixed value */
    (void)ctx;
#else
    *burstCount = 0;
    do {
        rc = TPM2_TIS_Read(ctx, TPM_BURST_COUNT(ctx->locality),
            (byte*)burstCount, sizeof(*burstCount));
        if (rc == TPM_RC_SUCCESS && *burstCount > 0)
            break;
        XTPM_WAIT();
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);

    if (*burstCount > MAX_SPI_FRAMESIZE)
        *burstCount = MAX_SPI_FRAMESIZE;

    if (timeout <= 0)
        return TPM_RC_TIMEOUT;
#endif

    return rc;
}

int TPM2_TIS_SendCommand(TPM2_CTX* ctx, byte* cmd, word16 cmdSz)
{
    int rc;
    int xferSz, pos;
    byte access, status = 0;
    word16 rspSz, burstCount;

#ifdef DEBUG_WOLFTPM
    printf("Command: %d\n", cmdSz);
    TPM2_PrintBin(cmd, cmdSz);
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
    while (pos < cmdSz) {
        rc = TPM2_TIS_GetBurstCount(ctx, &burstCount);
        if (rc < 0)
            goto exit;

        xferSz = cmdSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_Write(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                               xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;
        pos += xferSz;

        if (pos < cmdSz) {
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

#ifndef WOLFTPM_ST33
    /* Wait for TPM_STS_DATA_EXPECT = 0 and TPM_STS_VALID = 1 */
    rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT | TPM_STS_VALID,
                                     TPM_STS_VALID);
    if (rc != TPM_RC_SUCCESS) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_TIS_SendCommand status valid timeout!\n");
    #endif
        goto exit;
    }
#endif

    /* Execute Command */
    access = TPM_STS_GO;
    rc = TPM2_TIS_Write(ctx, TPM_STS(ctx->locality), &access,
                           sizeof(access));
    if (rc != TPM_RC_SUCCESS)
        goto exit;

    /* Read response */
    pos = 0;
    rspSz = sizeof(TPM2_HEADER); /* Read at least TPM header */
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
        if (rc < 0)
            goto exit;

        xferSz = rspSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_Read(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                              xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        pos += xferSz;

        /* Get real response size */
        if (pos == (int)sizeof(TPM2_HEADER)) {
            TPM2_HEADER* header = (TPM2_HEADER*)cmd;
            rspSz = TPM2_Packet_SwapU32(header->size);

            /* safety check for stuck FFFF case */
            if (rspSz == 0xFFFF) {
                rc = TPM_RC_FAILURE;
                goto exit;
            }
        }
    }

#ifdef DEBUG_WOLFTPM
    printf("Response: %d\n", rspSz);
    TPM2_PrintBin(cmd, rspSz);
#endif

    rc = TPM_RC_SUCCESS;

exit:

    /* Tell TPM we are done */
    if (rc == TPM_RC_SUCCESS)
        rc = TPM2_TIS_Ready(ctx);

    return rc;
}
/******************************************************************************/
/* --- END TPM Interface Layer -- */
/******************************************************************************/
