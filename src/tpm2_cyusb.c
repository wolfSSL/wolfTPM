/* tpm2_cyusb.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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


#ifdef WOLFTPM_CYUSB
#include <wolftpm/tpm2_cyusb.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_wrap.h>
/* TODO figure out instructions for acquiring Cypress libusb */
#include "../usb2go/cylib/common/header/CyUSBSerial.h"


/* Support a single TPM using Cypress UBS */
#ifndef TPM2_CYUSB_NUMBER
#define TPM2_CYUSB_NUMBER 0
#endif

/* LetsTrust USB2GO TPM2.0 stick has SPI as interface zero(0) */
#ifndef TPM2_CYUSB_INTERFACE
#define TPM2_CYUSB_INTERFACE 0
#endif

/* Talk to a TPM device through the Cypress USB2SPI converter and libusb */
int TPM2_CYUSB_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    BYTE numberOfDevices;
    CY_RETURN_STATUS rStatus;
    CY_HANDLE handle;
    CY_DATA_BUFFER writeBuf, readBuf;
    int deviceNumber = TPM2_CYUSB_NUMBER;
    int interfaceNumber=TPM2_CYUSB_INTERFACE;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    rStatus = CyLibraryInit();
    if (rStatus != CY_SUCCESS) {
        printf("CYUSB: Cypress USB library init failed ERRNO=%d\n", rStatus);
    }
    else {
        rStatus = CyGetListofDevices(&numberOfDevices);
        if (rStatus != CY_SUCCESS) {
            printf("CYUSB: Unable to get the list of devices ERRNO=%d\n", rStatus);
        }
        else if (numberOfDevices > 1) {
            printf("wolfTPM: Multiple TPM USB devices detected\n");
            printf("wolfTPM: Leave only one TPM USB stick and try again.\n");
        }
        else {
            rStatus = CyOpen(deviceNumber, interfaceNumber, &handle);
            if (rStatus != CY_SUCCESS) {
                printf("CYUSB: Unable to open the UBS device ERRNO=%d\n", rStatus);
            }

            writeBuf.length = packet->pos;
            writeBuf.buffer = packet->buf;
            /* TODO: Confirm the Cypress library can safely use one buffer */
            readBuf.buffer = packet->buf;

            /* Send the TPM command over the Cypress USB channel */
            CySpiReadWrite(handle, &readBuf, &writeBuf, 5000);

            /* The caller parses the TPM_Packet for correctness */
            if (readBuf.transferCount >= TPM2_HEADER_SIZE) {
               /* Enough bytes for a TPM response */
               packet->pos = readBuf.transferCount;
               rc = TPM_RC_SUCCESS;
            }

            CyClose(handle);
        }
    }

#ifdef WOLFTPM_DEBUG_VERBOSE
    if (rspSz > 0) {
        printf("Response size: %d\n", (int)rspSz);
        TPM2_PrintBin(packet->buf, rspSz);
    }
#endif

    (void)ctx;

    return rc;
}
#endif
