/* fwtpm_tis.h
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

/* fwTPM TIS (TPM Interface Specification) Register Emulation
 *
 * Shared header between fwTPM server and client HAL. Defines the
 * TIS register state layout and constants. The server-side transport
 * (POSIX shared memory, SPI slave, etc.) is abstracted via
 * FWTPM_TIS_HAL callbacks.
 */

#ifndef _FWTPM_TIS_H_
#define _FWTPM_TIS_H_

#include <wolftpm/tpm2_types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Shared memory and semaphore paths (POSIX transport defaults) */
#ifndef FWTPM_TIS_SHM_PATH
#define FWTPM_TIS_SHM_PATH     "/tmp/fwtpm.shm"
#endif
#ifndef FWTPM_TIS_SEM_CMD
#define FWTPM_TIS_SEM_CMD      "/fwtpm_cmd"
#endif
#ifndef FWTPM_TIS_SEM_RSP
#define FWTPM_TIS_SEM_RSP      "/fwtpm_rsp"
#endif

/* Magic and version for shared memory validation */
#define FWTPM_TIS_MAGIC         0x57544953UL  /* "WTIS" */
#define FWTPM_TIS_VERSION       1

/* Default burst count (bytes per FIFO transfer) */
#ifndef FWTPM_TIS_BURST_COUNT
#define FWTPM_TIS_BURST_COUNT   64
#endif

/* Maximum FIFO buffer size */
#ifndef FWTPM_TIS_FIFO_SIZE
#define FWTPM_TIS_FIFO_SIZE     4096
#endif

/* --- TIS Register Offsets (locality 0, SPI PTP spec) --- */
/* These match the defines in tpm2_tis.c with TPM_BASE_ADDRESS stripped */
#define FWTPM_TIS_ACCESS        0x0000u
#define FWTPM_TIS_INT_ENABLE    0x0008u
#define FWTPM_TIS_INT_VECTOR    0x000Cu
#define FWTPM_TIS_INT_STATUS    0x0010u
#define FWTPM_TIS_INTF_CAPS     0x0014u
#define FWTPM_TIS_STS           0x0018u
#define FWTPM_TIS_BURST_COUNT_REG 0x0019u /* 2 bytes within STS */
#define FWTPM_TIS_DATA_FIFO     0x0024u
#define FWTPM_TIS_XDATA_FIFO    0x0083u
#define FWTPM_TIS_DID_VID       0x0F00u
#define FWTPM_TIS_RID           0x0F04u

/* --- TIS ACCESS Register Bits --- */
#define FWTPM_ACCESS_VALID              0x80u
#define FWTPM_ACCESS_ACTIVE_LOCALITY    0x20u
#define FWTPM_ACCESS_REQUEST_PENDING    0x04u
#define FWTPM_ACCESS_REQUEST_USE        0x02u
#define FWTPM_ACCESS_ESTABLISHMENT      0x01u

/* --- TIS STS Register Bits --- */
#define FWTPM_STS_VALID                 0x80u
#define FWTPM_STS_COMMAND_READY         0x40u
#define FWTPM_STS_GO                    0x20u
#define FWTPM_STS_DATA_AVAIL            0x10u
#define FWTPM_STS_DATA_EXPECT           0x08u
#define FWTPM_STS_SELF_TEST_DONE        0x04u
#define FWTPM_STS_RESP_RETRY            0x02u

/* --- TIS Interface Capability Bits --- */
#define FWTPM_INTF_BURST_COUNT_STATIC   0x100u
#define FWTPM_INTF_CMD_READY_INT        0x080u
#define FWTPM_INTF_INT_LEVEL_LOW        0x010u
#define FWTPM_INTF_STS_VALID_INT        0x002u
#define FWTPM_INTF_DATA_AVAIL_INT       0x001u

/* --- TIS Register State ---
 * This struct holds the TIS register shadows and command/response FIFOs.
 * On desktop, it may be memory-mapped for shared-memory transport.
 * On embedded, it is a plain struct filled by SPI/I2C slave ISR. */
typedef struct FWTPM_TIS_REGS {
    /* Header */
    UINT32 magic;               /* FWTPM_TIS_MAGIC for validation */
    UINT32 version;             /* Protocol version */

    /* Register access request (client writes, server reads) */
    UINT32 reg_addr;            /* Register offset (locality stripped) */
    UINT32 reg_len;             /* Transfer length in bytes */
    BYTE   reg_is_write;        /* 1=write, 0=read */
    BYTE   reg_data[64];        /* Data for write or read result */

    /* TIS register shadow state (server owns, client reads) */
    UINT32 access;              /* TPM_ACCESS register */
    UINT32 sts;                 /* TPM_STS register (low byte = status,
                                 * upper 16 bits = burst count) */
    UINT32 int_enable;          /* TPM_INT_ENABLE register */
    UINT32 int_status;          /* TPM_INT_STATUS register */
    UINT32 intf_caps;           /* TPM_INTF_CAPS register */
    UINT32 did_vid;             /* TPM_DID_VID register */
    UINT32 rid;                 /* TPM_RID register */

    /* Command FIFO (client writes command bytes here) */
    BYTE   cmd_buf[FWTPM_TIS_FIFO_SIZE];
    UINT32 cmd_len;             /* Total command bytes written */
    UINT32 fifo_write_pos;      /* Current write position */

    /* Response FIFO (server writes response bytes here) */
    BYTE   rsp_buf[FWTPM_TIS_FIFO_SIZE];
    UINT32 rsp_len;             /* Total response length */
    UINT32 fifo_read_pos;       /* Current read position */
} FWTPM_TIS_REGS;

/* Backward compatibility alias */
typedef FWTPM_TIS_REGS FWTPM_TIS_SHM;


/* --- TIS Transport HAL (server-side) ---
 * Abstracts the transport between client and server for TIS register
 * accesses. Default implementation uses POSIX shared memory + semaphores.
 * Embedded implementations use SPI/I2C slave interrupts. */
#ifdef WOLFTPM_FWTPM

/* Forward declaration */
struct FWTPM_CTX;

typedef struct FWTPM_TIS_HAL {
    /* Initialize transport, allocate/map register state.
     * Must set *regs to point to the FWTPM_TIS_REGS instance.
     * Returns 0 on success. */
    int (*init)(void* ctx, FWTPM_TIS_REGS** regs);

    /* Block until a register access request is available.
     * Returns 0 on success, negative on error/shutdown.
     * Return -1 with errno==EINTR to continue the loop. */
    int (*wait_request)(void* ctx);

    /* Signal that a register access response is ready. */
    int (*signal_response)(void* ctx);

    /* Cleanup transport resources. */
    void (*cleanup)(void* ctx);

    /* User context (shm fds, SPI handle, event flags, etc.) */
    void* ctx;
} FWTPM_TIS_HAL;


/*!
    \ingroup wolfTPM_fwTPM
    \brief Register a custom TIS transport HAL. Must be called before
    FWTPM_TIS_Init. Allows embedded targets to plug in SPI/I2C slave
    implementations in place of the default POSIX shared memory
    transport.

    \return 0 on success
    \return BAD_FUNC_ARG if ctx or hal is NULL

    \param ctx pointer to an initialized FWTPM_CTX
    \param hal pointer to a caller-populated FWTPM_TIS_HAL

    \sa FWTPM_TIS_Init
    \sa FWTPM_TIS_SetDefaultHAL
*/
WOLFTPM_API int FWTPM_TIS_SetHAL(struct FWTPM_CTX* ctx,
    FWTPM_TIS_HAL* hal);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Initialize TIS transport and register-shadow state. If no
    HAL has been set, installs the default POSIX shared-memory HAL.

    \return 0 on success
    \return negative on transport initialization error

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_TIS_Cleanup
    \sa FWTPM_TIS_ServerLoop
*/
WOLFTPM_API int FWTPM_TIS_Init(struct FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Release TIS transport resources.

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_TIS_Init
*/
WOLFTPM_API void FWTPM_TIS_Cleanup(struct FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Run the TIS server loop. Waits for register-access requests
    from the HAL, applies them to the TIS register shadows, and
    dispatches completed commands to FWTPM_ProcessCommand.

    \return 0 on clean shutdown
    \return negative on fatal transport error

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_IO_RequestStop
*/
WOLFTPM_API int FWTPM_TIS_ServerLoop(struct FWTPM_CTX* ctx);

/*!
    \ingroup wolfTPM_fwTPM
    \brief Install the default POSIX shared-memory TIS HAL. Called
    implicitly by FWTPM_TIS_Init when no HAL was registered.

    \param ctx pointer to an initialized FWTPM_CTX

    \sa FWTPM_TIS_SetHAL
*/
WOLFTPM_API void FWTPM_TIS_SetDefaultHAL(struct FWTPM_CTX* ctx);

#endif /* WOLFTPM_FWTPM */


/* --- Client-side API (HAL for connecting to fwTPM via shm) --- */
#ifdef WOLFTPM_FWTPM_HAL

/* Client context for shared memory connection */
typedef struct FWTPM_TIS_CLIENT_CTX {
    FWTPM_TIS_REGS* shm;       /* mmap pointer */
    int shmFd;                  /* shm file descriptor */
    void* semCmd;               /* sem_t* command semaphore */
    void* semRsp;               /* sem_t* response semaphore */
} FWTPM_TIS_CLIENT_CTX;

/* Connect to existing fwTPM shared memory */
WOLFTPM_LOCAL int FWTPM_TIS_ClientConnect(FWTPM_TIS_CLIENT_CTX* client);

/* Disconnect from fwTPM shared memory */
WOLFTPM_LOCAL void FWTPM_TIS_ClientDisconnect(FWTPM_TIS_CLIENT_CTX* client);

#endif /* WOLFTPM_FWTPM_HAL */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _FWTPM_TIS_H_ */
