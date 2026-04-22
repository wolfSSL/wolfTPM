/* fwtpm_tis.c
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

/* fwTPM TIS Slave - Transport-Agnostic Register State Machine
 *
 * Implements the server side of the TIS register interface. The actual
 * transport (shared memory, SPI slave, etc.) is provided by the
 * FWTPM_TIS_HAL callbacks. This file contains only the register
 * access logic and server loop.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#if defined(WOLFTPM_FWTPM) && defined(WOLFTPM_FWTPM_TIS)

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_tis.h>
#include <wolftpm/fwtpm/fwtpm_command.h>
#include <wolftpm/fwtpm/fwtpm_io.h>

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
#include <signal.h>
#endif

/* Manufacturer DID:VID for identification.
 * VID = "WF" (0x4657), DID = "TP" (0x5054) */
#define FWTPM_TIS_DID_VID_VAL  0x50544657UL

/* --- Static helpers --- */

/* Extract register offset from a full TIS address.
 * TIS addresses are: TPM_BASE_ADDRESS | offset | (locality << 12)
 * For locality 0: address = 0xD40000 | offset
 * We mask off the base and locality bits to get just the register offset. */
static UINT32 TisRegOffset(UINT32 addr)
{
    return addr & 0x0FFFu;
}

/* Build STS register value with burst count in bits 8-23 */
static UINT32 TisBuildSts(BYTE stsFlags, UINT16 burstCount)
{
    return ((UINT32)burstCount << 8) | (UINT32)stsFlags;
}

/* Handle a single TIS register access */
static void TisHandleRegAccess(FWTPM_CTX* ctx, FWTPM_TIS_REGS* regs)
{
    UINT32 offset = TisRegOffset(regs->reg_addr);
    UINT32 len = regs->reg_len;
    FWTPM_DECLARE_BUF(localCmd, FWTPM_TIS_FIFO_SIZE);

    if (regs->reg_is_write) {
        /* --- Write operations --- */
        UINT32 val = 0;
        if (len >= 1) val = regs->reg_data[0];
        if (len >= 2) val |= (UINT32)regs->reg_data[1] << 8;
        if (len >= 3) val |= (UINT32)regs->reg_data[2] << 16;
        if (len >= 4) val |= (UINT32)regs->reg_data[3] << 24;

        switch (offset) {
            case FWTPM_TIS_ACCESS:
                if (val & FWTPM_ACCESS_REQUEST_USE) {
                    /* Grant locality 0 */
                    regs->access = FWTPM_ACCESS_VALID |
                                  FWTPM_ACCESS_ACTIVE_LOCALITY;
                    regs->sts = TisBuildSts(
                        FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY,
                        FWTPM_TIS_BURST_COUNT);
                }
                if (val & FWTPM_ACCESS_ACTIVE_LOCALITY) {
                    /* Release locality */
                    regs->access = FWTPM_ACCESS_VALID;
                    regs->sts = TisBuildSts(0, 0);
                }
                break;

            case FWTPM_TIS_STS:
            case FWTPM_TIS_STS + 1: /* burst count write (ignored) */
                if (val & FWTPM_STS_COMMAND_READY) {
                    /* Reset FIFO for new command */
                    regs->cmd_len = 0;
                    regs->fifo_write_pos = 0;
                    regs->fifo_read_pos = 0;
                    regs->rsp_len = 0;
                    regs->sts = TisBuildSts(
                        FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY,
                        FWTPM_TIS_BURST_COUNT);
                }
                if (val & FWTPM_STS_GO) {
                    /* Execute command - copy to local buffer first to
                     * prevent TOCTOU if cmd_buf is in shared memory */
                    UINT32 localCmdLen;
                    int rspSize = 0;
                    int procRc;

                    FWTPM_ALLOC_BUF(localCmd, FWTPM_TIS_FIFO_SIZE);

                    localCmdLen = regs->cmd_len;
                    if (localCmdLen > FWTPM_TIS_FIFO_SIZE) {
                        localCmdLen = FWTPM_TIS_FIFO_SIZE;
                    }
                    XMEMCPY(localCmd, regs->cmd_buf, localCmdLen);

                #ifdef DEBUG_WOLFTPM
                    printf("fwTPM TIS: GO cmd_len=%u\n", localCmdLen);
                #endif

                    procRc = FWTPM_ProcessCommand(ctx,
                        localCmd, (int)localCmdLen,
                        regs->rsp_buf, &rspSize, 0 /* locality */);
                    FWTPM_FREE_BUF(localCmd);
                    if (procRc != TPM_RC_SUCCESS || rspSize == 0) {
                        /* Build minimal error response
                         * TPM_ST_NO_SESSIONS = 0x8001 (big-endian) */
                        regs->rsp_buf[0] = 0x80;
                        regs->rsp_buf[1] = 0x01; /* TPM_ST_NO_SESSIONS */
                        regs->rsp_buf[2] = 0x00;
                        regs->rsp_buf[3] = 0x00;
                        regs->rsp_buf[4] = 0x00;
                        regs->rsp_buf[5] = 0x0A; /* size = 10 */
                        regs->rsp_buf[6] = 0x00;
                        regs->rsp_buf[7] = 0x00;
                        regs->rsp_buf[8] = 0x01;
                        regs->rsp_buf[9] = 0x01; /* TPM_RC_FAILURE */
                        rspSize = 10;
                    }
                    regs->rsp_len = (UINT32)rspSize;
                    regs->fifo_read_pos = 0;
                    regs->sts = TisBuildSts(
                        FWTPM_STS_VALID | FWTPM_STS_DATA_AVAIL,
                        FWTPM_TIS_BURST_COUNT);
                }
                if (val & FWTPM_STS_RESP_RETRY) {
                    /* Reset read position to re-read response */
                    regs->fifo_read_pos = 0;
                    if (regs->rsp_len > 0) {
                        regs->sts = TisBuildSts(
                            FWTPM_STS_VALID | FWTPM_STS_DATA_AVAIL,
                            FWTPM_TIS_BURST_COUNT);
                    }
                }
                break;

            case FWTPM_TIS_DATA_FIFO:
            case FWTPM_TIS_XDATA_FIFO: {
                /* Write command data to FIFO */
                UINT32 i;
                UINT32 space;
                /* Snapshot write position to local for TOCTOU safety */
                UINT32 wpos = regs->fifo_write_pos;
                if (wpos >= FWTPM_TIS_FIFO_SIZE) {
                    regs->fifo_write_pos = 0;
                    break;
                }
                /* Clamp len to reg_data buffer size */
                if (len > sizeof(regs->reg_data)) {
                    len = (UINT32)sizeof(regs->reg_data);
                }
                space = FWTPM_TIS_FIFO_SIZE - wpos;
                if (len > space) {
                    len = space;
                }
                for (i = 0; i < len; i++) {
                    regs->cmd_buf[wpos++] = regs->reg_data[i];
                }
                regs->fifo_write_pos = wpos;
                regs->cmd_len = wpos;

                /* Set EXPECT while we still expect more data */
                regs->sts = TisBuildSts(
                    FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY |
                    FWTPM_STS_DATA_EXPECT,
                    FWTPM_TIS_BURST_COUNT);

                /* If we have the full TPM header (TPM2_HEADER_SIZE bytes),
                 * check if command is complete based on the size field
                 * in bytes [2..5] */
                if (regs->cmd_len >= TPM2_HEADER_SIZE) {
                    UINT32 cmdTotalSz = FwLoadU32BE(regs->cmd_buf + 2);
                    if (cmdTotalSz < TPM2_HEADER_SIZE ||
                        cmdTotalSz > FWTPM_TIS_FIFO_SIZE) {
                        /* Invalid command size, reset FIFO */
                        regs->cmd_len = 0;
                        regs->fifo_write_pos = 0;
                        regs->sts = TisBuildSts(
                            FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY,
                            FWTPM_TIS_BURST_COUNT);
                        break;
                    }
                    if (regs->cmd_len >= cmdTotalSz) {
                        /* Full command received, clear EXPECT */
                        regs->sts = TisBuildSts(
                            FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY,
                            FWTPM_TIS_BURST_COUNT);
                    }
                }
                break;
            }

            case FWTPM_TIS_INT_ENABLE:
                regs->int_enable = val;
                break;

            case FWTPM_TIS_INT_STATUS:
                /* Write-1-to-clear */
                regs->int_status &= ~val;
                break;

            default:
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM TIS: write to unknown reg 0x%04x\n", offset);
            #endif
                break;
        }
    }
    else {
        /* --- Read operations --- */
        UINT32 val = 0;

        switch (offset) {
            case FWTPM_TIS_ACCESS:
                val = regs->access;
                break;

            case FWTPM_TIS_STS:
                val = regs->sts;
                break;

            case FWTPM_TIS_BURST_COUNT_REG:
                /* Burst count is at offset 0x0019, which is bytes [1..2]
                 * of the 4-byte STS register. Return just the burst count
                 * portion (upper 16 bits shifted down). */
                val = (regs->sts >> 8) & 0xFFFFu;
                break;

            case FWTPM_TIS_DATA_FIFO:
            case FWTPM_TIS_XDATA_FIFO: {
                /* Read response data from FIFO */
                UINT32 i;
                UINT32 avail;
                /* Snapshot read state to locals for TOCTOU safety */
                UINT32 rpos = regs->fifo_read_pos;
                UINT32 rlen = regs->rsp_len;
                /* Zero full reg_data first: client may copy more bytes than
                 * we write here (it uses its originally-requested size, not
                 * our clamped len), so any stale shared-memory bytes would
                 * leak prior-operation data into the client. */
                XMEMSET(regs->reg_data, 0, sizeof(regs->reg_data));
                if (rpos > rlen || rpos >= sizeof(regs->rsp_buf)) {
                    avail = 0;
                }
                else {
                    avail = rlen - rpos;
                }
                if (len > avail) {
                    len = avail;
                }
                if (len > sizeof(regs->reg_data)) {
                    len = (UINT32)sizeof(regs->reg_data);
                }
                for (i = 0; i < len; i++) {
                    regs->reg_data[i] = regs->rsp_buf[rpos++];
                }
                regs->fifo_read_pos = rpos;
                /* Update data availability */
                if (rpos >= rlen) {
                    /* All response bytes read */
                    regs->sts = TisBuildSts(
                        FWTPM_STS_VALID | FWTPM_STS_COMMAND_READY,
                        FWTPM_TIS_BURST_COUNT);
                }
                /* Return early - data already in reg_data */
                return;
            }

            case FWTPM_TIS_INT_ENABLE:
                val = regs->int_enable;
                break;

            case FWTPM_TIS_INT_VECTOR:
                val = 0; /* no interrupt vector */
                break;

            case FWTPM_TIS_INT_STATUS:
                val = regs->int_status;
                break;

            case FWTPM_TIS_INTF_CAPS:
                val = regs->intf_caps;
                break;

            case FWTPM_TIS_DID_VID:
                val = regs->did_vid;
                break;

            case FWTPM_TIS_RID:
                val = regs->rid;
                break;

            default:
            #ifdef DEBUG_WOLFTPM
                printf("fwTPM TIS: read from unknown reg 0x%04x\n", offset);
            #endif
                break;
        }

        /* Clamp len for scalar registers (max 4 bytes) and zero-fill
         * to prevent stale data in reg_data from being read back */
        if (len > 4) {
            len = 4;
        }
        XMEMSET(regs->reg_data, 0, sizeof(regs->reg_data));
        /* Pack value into reg_data (little-endian, matching TIS spec) */
        if (len >= 1) regs->reg_data[0] = (BYTE)(val);
        if (len >= 2) regs->reg_data[1] = (BYTE)(val >> 8);
        if (len >= 3) regs->reg_data[2] = (BYTE)(val >> 16);
        if (len >= 4) regs->reg_data[3] = (BYTE)(val >> 24);
    }
}


/* --- Public API --- */

int FWTPM_TIS_SetHAL(FWTPM_CTX* ctx, FWTPM_TIS_HAL* hal)
{
    if (ctx == NULL || hal == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&ctx->tisHal, hal, sizeof(FWTPM_TIS_HAL));
    return TPM_RC_SUCCESS;
}

int FWTPM_TIS_Init(FWTPM_CTX* ctx)
{
    FWTPM_TIS_REGS* regs;
    int rc;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* If no HAL set, use default POSIX shared memory */
    if (ctx->tisHal.init == NULL) {
        FWTPM_TIS_SetDefaultHAL(ctx);
    }

    rc = ctx->tisHal.init(ctx->tisHal.ctx, &regs);
    if (rc != 0) {
        return TPM_RC_FAILURE;
    }

    ctx->tisRegs = regs;

    /* Initialize register state */
    XMEMSET(regs, 0, sizeof(FWTPM_TIS_REGS));
    regs->magic = FWTPM_TIS_MAGIC;
    regs->version = FWTPM_TIS_VERSION;

    /* Power-on register defaults */
    regs->access = FWTPM_ACCESS_VALID;
    regs->sts = TisBuildSts(0, 0);
    regs->intf_caps = FWTPM_INTF_BURST_COUNT_STATIC |
                     FWTPM_INTF_DATA_AVAIL_INT |
                     FWTPM_INTF_STS_VALID_INT |
                     FWTPM_INTF_CMD_READY_INT |
                     FWTPM_INTF_INT_LEVEL_LOW;
    regs->did_vid = FWTPM_TIS_DID_VID_VAL;
    regs->rid = FWTPM_VERSION_PATCH;

    /* Auto power-on in TIS mode (no platform port to signal power) */
    ctx->powerOn = 1;

    return TPM_RC_SUCCESS;
}

void FWTPM_TIS_Cleanup(FWTPM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->tisHal.cleanup != NULL) {
        ctx->tisHal.cleanup(ctx->tisHal.ctx);
    }
    ctx->tisRegs = NULL;
}

int FWTPM_TIS_ServerLoop(FWTPM_CTX* ctx)
{
    FWTPM_TIS_HAL* hal;
    FWTPM_TIS_REGS* regs;
    TPM_RC retRc = TPM_RC_SUCCESS;
    int rc;
#ifndef _WIN32
    struct sigaction sa;
#endif

    if (ctx == NULL || ctx->tisRegs == NULL ||
        ctx->tisHal.wait_request == NULL) {
        return BAD_FUNC_ARG;
    }

    hal = &ctx->tisHal;
    regs = ctx->tisRegs;
    ctx->running = 1;

#ifndef _WIN32
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);
#endif

    printf("fwTPM TIS: Server ready, waiting for register accesses...\n");

    while (ctx->running) {
        /* Propagate async stop request (from signal handler) into
         * ctx state, matching FWTPM_IO_ServerLoop behavior */
        if (FWTPM_IO_IsStopRequested()) {
            ctx->running = 0;
            break;
        }

        /* Wait for client to signal a register access */
        rc = hal->wait_request(hal->ctx);
        if (rc == -1) {
            /* EINTR or transient — re-check stop flag before retry */
            continue;
        }
        if (rc < 0) {
            /* Fatal HAL error — propagate so the caller can distinguish
             * this from a clean shutdown via ctx->running=0. */
            retRc = TPM_RC_FAILURE;
            break;
        }

        /* Process the register access */
        TisHandleRegAccess(ctx, regs);

        /* Signal client that register access is complete */
        if (hal->signal_response != NULL) {
            hal->signal_response(hal->ctx);
        }
    }

    return retRc;
}

#endif /* WOLFTPM_FWTPM && WOLFTPM_FWTPM_TIS */
