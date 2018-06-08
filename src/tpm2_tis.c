
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

#define TPM_TIS_SPI_READ        0x80
#define TPM_TIS_SPI_WRITE       0x00

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

#define TPM_BASE_ADDRESS (0xd40000u)

#define TPM_ACCESS(l)           (TPM_BASE_ADDRESS | 0x0000u | ((l) << 12u))
#define TPM_INT_ENABLE(l)       (TPM_BASE_ADDRESS | 0x0008u | ((l) << 12u))
#define TPM_INT_VECTOR(l)       (TPM_BASE_ADDRESS | 0x000Cu | ((l) << 12u))
#define TPM_INT_STATUS(l)       (TPM_BASE_ADDRESS | 0x0010u | ((l) << 12u))
#define TPM_INTF_CAPS(l)        (TPM_BASE_ADDRESS | 0x0014u | ((l) << 12u))
#define TPM_STS(l)              (TPM_BASE_ADDRESS | 0x0018u | ((l) << 12u))
#define TPM_STS3(l)             (TPM_BASE_ADDRESS | 0x001bu | ((l) << 12u))
#define TPM_DATA_FIFO(l)        (TPM_BASE_ADDRESS | 0x0024u | ((l) << 12u))

#define TPM_DID_VID(l)          (TPM_BASE_ADDRESS | 0x0F00u | ((l) << 12u))
#define TPM_RID(l)              (TPM_BASE_ADDRESS | 0x0F04u | ((l) << 12u))


int TPM2_TIS_SpiRead(TPM2_CTX* ctx, word32 addr, byte* result,
    word32 len)
{
    int rc;
    byte txBuf[MAX_SPI_FRAMESIZE+4];
    byte rxBuf[MAX_SPI_FRAMESIZE+4];

    if (ctx == NULL || result == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    txBuf[0] = TPM_TIS_SPI_READ | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMSET(&txBuf[4], 0, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + 4, ctx->userCtx);

    XMEMCPY(result, &rxBuf[4], len);

    return rc;
}

int TPM2_TIS_SpiWrite(TPM2_CTX* ctx, word32 addr, const byte* value,
    word32 len)
{
    int rc;
    byte txBuf[MAX_SPI_FRAMESIZE+4];
    byte rxBuf[MAX_SPI_FRAMESIZE+4];

    if (ctx == NULL || value == NULL || len == 0 || len > MAX_SPI_FRAMESIZE)
        return BAD_FUNC_ARG;

    txBuf[0] = TPM_TIS_SPI_WRITE | ((len & 0xFF) - 1);
    txBuf[1] = (addr>>16) & 0xFF;
    txBuf[2] = (addr>>8)  & 0xFF;
    txBuf[3] = (addr)     & 0xFF;
    XMEMCPY(&txBuf[4], value, len);

    rc = ctx->ioCb(ctx, txBuf, rxBuf, len + 4, ctx->userCtx);

    return rc;
}

int TPM2_TIS_StartupWait(TPM2_CTX* ctx, int timeout)
{
    int rc;
    byte access = 0;

    do {
        rc = TPM2_TIS_SpiRead(ctx, TPM_ACCESS(0), &access, sizeof(access));
        if (access & TPM_ACCESS_VALID)
            return 0;
    } while (rc == TPM_RC_SUCCESS && --timeout > 0);
    return -1;
}

int TPM2_TIS_CheckLocality(TPM2_CTX* ctx, int locality)
{
    int rc;
    byte access;

    rc = TPM2_TIS_SpiRead(ctx, TPM_ACCESS(locality), &access, sizeof(access));
    if (rc == TPM_RC_SUCCESS &&
        ((access & (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) ==
                   (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID))) {
        ctx->locality = locality;
        return locality;
    }
    return -1;
}

int TPM2_TIS_RequestLocality(TPM2_CTX* ctx, int timeout)
{
    int rc;
    int locality = 0;
    byte access;

    rc = TPM2_TIS_CheckLocality(ctx, locality);
    if (rc >= 0)
        return rc;

    access = TPM_ACCESS_REQUEST_USE;
    rc = TPM2_TIS_SpiWrite(ctx, TPM_ACCESS(locality), &access, sizeof(access));
    if (rc == TPM_RC_SUCCESS) {
        do {
            rc = TPM2_TIS_CheckLocality(ctx, locality);
            if (rc >= 0)
                return rc;
        } while (--timeout > 0);
    }

    return -1;
}

int TPM2_TIS_GetInfo(TPM2_CTX* ctx)
{
    word32 reg;
    int rc;

    rc = TPM2_TIS_SpiRead(ctx, TPM_INTF_CAPS(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->caps = reg;
    }

    rc = TPM2_TIS_SpiRead(ctx, TPM_DID_VID(ctx->locality), (byte*)&reg,
        sizeof(reg));
    if (rc == TPM_RC_SUCCESS) {
        ctx->did_vid = reg;
    }

    reg = 0;
    rc = TPM2_TIS_SpiRead(ctx, TPM_RID(ctx->locality), (byte*)&reg, 1);
    if (rc == TPM_RC_SUCCESS) {
        ctx->rid = reg;
    }

    return rc;
}

byte TPM2_TIS_Status(TPM2_CTX* ctx)
{
    byte status = 0;
    TPM2_TIS_SpiRead(ctx, TPM_STS(ctx->locality), &status, sizeof(status));
    return status;
}

byte TPM2_TIS_WaitForStatus(TPM2_CTX* ctx, byte status, byte status_mask)
{
    byte reg;
    int timeout = TPM_TIMEOUT_TRIES;
    do {
        reg = TPM2_TIS_Status(ctx);
    } while (((reg & status) != status_mask) && --timeout > 0);
    if (timeout <= 0)
        return 1;
    return 0;
}

int TPM2_TIS_Ready(TPM2_CTX* ctx)
{
    byte status = TPM_STS_COMMAND_READY;
    return TPM2_TIS_SpiWrite(ctx, TPM_STS(ctx->locality), &status, sizeof(status));
}

int TPM2_TIS_GetBurstCount(TPM2_CTX* ctx)
{
    int rc;
    word16 burstCount;

    do {
        rc = TPM2_TIS_SpiRead(ctx, TPM_STS(ctx->locality) + 1,
            (byte*)&burstCount, sizeof(burstCount));
        if (rc != TPM_RC_SUCCESS)
            return -1;
    } while (burstCount == 0);

    if (burstCount > MAX_SPI_FRAMESIZE)
        burstCount = MAX_SPI_FRAMESIZE;

    if (rc == TPM_RC_SUCCESS)
        return burstCount;

    return 0;
}

int TPM2_TIS_SendCommand(TPM2_CTX* ctx, byte* cmd, word16 cmdSz)
{
    int rc;
    int status, xferSz, pos, burstCount;
    byte access;
    word16 rspSz;

#ifdef DEBUG_WOLFTPM
    printf("Command: %d\n", cmdSz);
    TPM2_PrintBin(cmd, cmdSz);
#endif

    /* Make sure TPM is ready for command */
    status = TPM2_TIS_Status(ctx);
    if ((status & TPM_STS_COMMAND_READY) == 0) {
        /* Tell TPM chip to expect a command */
        rc = TPM2_TIS_Ready(ctx);
        if (rc != 0)
            goto exit;

        /* Wait for command ready (TPM_STS_COMMAND_READY = 1) */
        rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_COMMAND_READY,
                                         TPM_STS_COMMAND_READY);
        if (rc != 0)
            goto exit;
    }

    /* Write Command */
    pos = 0;
    while (pos < cmdSz) {
        burstCount = TPM2_TIS_GetBurstCount(ctx);
        if (burstCount < 0) {
            rc = burstCount; goto exit;
        }

        xferSz = cmdSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_SpiWrite(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                               xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;
        pos += xferSz;

        if (pos < cmdSz) {
            /* Wait for expect more data (TPM_STS_DATA_EXPECT = 1) */
            rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT,
                                             TPM_STS_DATA_EXPECT);
            if (rc != 0) {
            #ifdef DEBUG_WOLFTPM
                printf("TPM2_TIS_SendCommand write expected more data!\n");
            #endif
                goto exit;
            }
        }
    }

    /* Wait for TPM_STS_DATA_EXPECT = 0 and TPM_STS_VALID = 1 */
    rc = TPM2_TIS_WaitForStatus(ctx, TPM_STS_DATA_EXPECT | TPM_STS_VALID,
                                     TPM_STS_VALID);
    if (rc != 0) {
    #ifdef DEBUG_WOLFTPM
        printf("TPM2_TIS_SendCommand status valid timeout!\n");
    #endif
        goto exit;
    }

    /* Execute Command */
    access = TPM_STS_GO;
    rc = TPM2_TIS_SpiWrite(ctx, TPM_STS(ctx->locality), &access,
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
        if (rc != 0) {
        #ifdef DEBUG_WOLFTPM
            printf("TPM2_TIS_SendCommand read no data available!\n");
        #endif
            goto exit;
        }

        burstCount = TPM2_TIS_GetBurstCount(ctx);
        if (burstCount < 0) {
            rc = burstCount; goto exit;
        }

        xferSz = rspSz - pos;
        if (xferSz > burstCount)
            xferSz = burstCount;

        rc = TPM2_TIS_SpiRead(ctx, TPM_DATA_FIFO(ctx->locality), &cmd[pos],
                              xferSz);
        if (rc != TPM_RC_SUCCESS)
            goto exit;

        pos += xferSz;

        /* Get real response size */
        if (pos == (int)sizeof(TPM2_HEADER)) {
            TPM2_HEADER* header = (TPM2_HEADER*)cmd;
            rspSz = TPM2_Packet_SwapU32(header->size);
        }
    }

#ifdef DEBUG_WOLFTPM
    printf("Response: %d\n", rspSz);
    TPM2_PrintBin(cmd, rspSz);
#endif

    rc = 0;

exit:

    /* Tell TPM we are done */
    if (rc == 0)
        rc = TPM2_TIS_Ready(ctx);

    return rc;
}
/******************************************************************************/
/* --- END TPM Interface Layer -- */
/******************************************************************************/
