/* tpm2_spdm.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* SPDM Secure Session Support for wolfTPM
 *
 * Implements SPDM (Security Protocol and Data Model) secure communication
 * between host and TPM using the wolfSPDM library for all protocol operations.
 *
 * References:
 * - DMTF DSP0274 (SPDM v1.2/1.3)
 * - TCG SPDM Binding for Secure Communication v1.0
 * - TCG TPM 2.0 Library Specification v1.84
 *
 * Architecture:
 *   Application -> wolfTPM2 Wrapper -> SPDM Transport (this module) -> SPI HAL
 *                                            |
 *                                      wolfSPDM library (spdm/ subdirectory)
 *                                      (all SPDM protocol logic)
 *
 * This module provides:
 * - SPDM context management (init/free)
 * - Secured exchange with VENDOR_DEFINED wrapping (Nuvoton)
 * - TPM-specific SPDM enable/disable via NTC2 vendor commands
 * - I/O callback adapter to route wolfSPDM through TPM transport
 *
 * wolfSPDM (spdm/) provides:
 * - Full SPDM protocol implementation (handshake, key derivation, encryption)
 * - Standard and Nuvoton mode support
 * - TCG binding message framing (for Nuvoton TPMs)
 * - All cryptographic operations
 */

#ifndef __TPM2_SPDM_H__
#define __TPM2_SPDM_H__

#include <wolftpm/tpm2.h>

#ifdef WOLFTPM_SPDM

/* wolfSPDM library provides all SPDM protocol implementation */
#include <wolftpm/spdm/spdm.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Forward declarations */
struct WOLFTPM2_SPDM_CTX;

/* -------------------------------------------------------------------------- */
/* SPDM Context
 *
 * This is a thin wrapper around WOLFSPDM_CTX. wolfSPDM handles all the
 * SPDM protocol state, key derivation, and encryption. This context adds
 * only TPM-specific fields needed for integration with wolfTPM2.
 * -------------------------------------------------------------------------- */

typedef struct WOLFTPM2_SPDM_CTX {
    /* wolfSPDM context - handles all SPDM protocol operations */
    WOLFSPDM_CTX* spdmCtx;

    /* Reference to TPM context for NTC2 vendor commands */
    TPM2_CTX* tpmCtx;

    /* SPDM-only mode tracking (for Nuvoton TPMs) */
    int spdmOnlyLocked;

#ifndef WOLFTPM_SMALL_STACK
    /* Static wolfSPDM context buffer, aligned for WOLFSPDM_CTX cast */
    XGEN_ALIGN byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
#endif
} WOLFTPM2_SPDM_CTX;

/* -------------------------------------------------------------------------- */
/* SPDM Core API Functions
 * -------------------------------------------------------------------------- */

/**
 * Initialize SPDM context with wolfSPDM.
 * Must be called before any other SPDM function.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param ioCb      I/O callback for sending/receiving SPDM messages
 * @param userCtx   User context passed to the I/O callback
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_InitCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    WOLFSPDM_IO_CB ioCb,
    void* userCtx
);

/**
 * Set the TPM context for NTC2 vendor commands.
 * Only needed for Nuvoton TPMs when using wolfTPM2_SPDM_Enable().
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param tpmCtx    TPM2 context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SetTPMCtx(
    WOLFTPM2_SPDM_CTX* ctx,
    TPM2_CTX* tpmCtx
);

/**
 * Enable SPDM on the TPM via NTC2_PreConfig.
 * Requires platform hierarchy authorization.
 * TPM must be reset after this for SPDM to take effect.
 * NOTE: This is a Nuvoton-specific feature.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_Enable(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Disable SPDM on a Nuvoton TPM via NTC2_PreConfig.
 * Sets Cfg_H bit 1 to disable SPDM. Requires TPM reset to take effect.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_Disable(
    WOLFTPM2_SPDM_CTX* ctx
);

/**
 * Perform a secured message exchange (encrypt, send, receive, decrypt).
 * Wraps wolfSPDM_SecuredExchange() for TPM command/response.
 *
 * @param ctx       wolfTPM2 SPDM context
 * @param cmdPlain  Plaintext command to send
 * @param cmdSz     Size of command
 * @param rspPlain  Buffer for plaintext response
 * @param rspSz     [in] Size of response buffer, [out] Actual response size
 * @return 0 on success, negative on error
 */
WOLFTPM_API int wolfTPM2_SPDM_SecuredExchange(
    WOLFTPM2_SPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz
);

/**
 * Free all SPDM context resources.
 * Safe to call on an already-cleaned-up or zero-initialized context.
 *
 * @param ctx       wolfTPM2 SPDM context
 */
WOLFTPM_API void wolfTPM2_SPDM_FreeCtx(
    WOLFTPM2_SPDM_CTX* ctx
);

/* -------------------------------------------------------------------------- */
/* Nuvoton-Specific Functions (requires wolfSPDM with --enable-nuvoton)
 * -------------------------------------------------------------------------- */

#ifdef WOLFTPM_SPDM_TCG

/**
 * Set the built-in TIS I/O callback for routing SPDM through TPM SPI/I2C.
 * Uses the TPM TIS FIFO to send/receive raw SPDM messages.
 * TCG framing is handled internally by wolfSPDM_SendReceive().
 * Must be called after wolfTPM2_SPDM_InitCtx() and SetTPMCtx().
 *
 * Only available on hardware TPM builds (not LINUX_DEV, SWTPM, or WINAPI).
 *
 * @param ctx       wolfTPM2 SPDM context (with tpmCtx already set)
 * @return 0 on success, NOT_COMPILED_IN if TIS not available
 */
WOLFTPM_API int wolfTPM2_SPDM_SetTisIO(
    WOLFTPM2_SPDM_CTX* ctx
);

#endif /* WOLFTPM_SPDM_TCG */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFTPM_SPDM */

#endif /* __TPM2_SPDM_H__ */
