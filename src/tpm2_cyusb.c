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
/* TODO figure out a good way for acquiring and including the Cypress libusb */
#include "../usb2go/cylib/common/header/CyUSBSerial.h"


/* LetsTrust USB2GO TPM2.0 stick has SPI as interface zero(0) */
#ifndef TPM2_CYUSB_INTERFACE
#define TPM2_CYUSB_INTERFACE 0
#endif

#define TPM2_CYUSB_RC_NODEVICE (-1)
#define TPM2_CYUSB_SIGNATURE_LENGTH 6

/* Helper function to check Cypress magic value(signature */
static int TPM2_CYUSB_VerifySignature(int deviceNumber)
{
    int rc = FALSE;
    CY_HANDLE handle;
    CY_RETURN_STATUS rStatus;
    BYTE signature[TPM2_CYUSB_SIGNATURE_LENGTH];

    rStatus = CyOpen(deviceNumber, TPM2_CYUSB_INTERFACE, &handle);
    if (rStatus == CY_SUCCESS) {
        rStatus = CyGetSignature(handle, signature);

        rc = (rStatus == CY_SUCCESS) ? TRUE : FALSE;

        CyClose (handle);
    }

    return rc;
}


/* Helper function to find a Cypress USB2SPI device
 *
 * Matches Cypress signature, device class and interface type
 *
 * Return value
 * On success, the number of the device on the UBS bus
 * On failure, TPM2_CYUSB_RC_NODEVICE is returned
 */
static int TPM2_CYUSB_FindDevice(int* deviceNumber) {
    int devNum = TPM2_CYUSB_RC_NODEVICE;
    BYTE deviceCount;
    CY_DEVICE_INFO deviceInfo;
    CY_RETURN_STATUS rStatus;

    rStatus = CyGetListofDevices(&deviceCount);
    if (rStatus != CY_SUCCESS) {
        printf("CYUSB: Unable to get the list of devices ERRNO=%d\n", rStatus);
        return TPM_RC_FAILURE;
    }

#ifdef DEBUG_WOLFTPM
     printf("The first USB2SPI device found is tried as TPM2.0 on USB\n");
#endif

    for(devNum=0; devNum < deviceCount; devNum++) {
        rStatus = CyGetDeviceInfo (devNum, &deviceInfo);
        if (!rStatus) {
            /* Verify magic Cypress value(signature) */
            if (!TPM2_CYUSB_VerifySignature(devNum)) {
                continue;
            }
            /* Verify this is indeed a Cypress UBS bridge for SPI */
            if (deviceInfo.deviceClass[TPM2_CYUSB_INTERFACE] == CY_CLASS_VENDOR) {
                if(deviceInfo.deviceType[TPM2_CYUSB_INTERFACE] == CY_TYPE_SPI) {
                    break;
                }
            }
        }
    }

    *deviceNumber = devNum;
    return TPM_RC_SUCCESS;
}

/* Talk to a TPM device through the Cypress USB2SPI converter and libusb */
int TPM2_CYUSB_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int rc = TPM_RC_FAILURE;
    CY_RETURN_STATUS rStatus;
    CY_HANDLE handle;
    CY_DATA_BUFFER writeBuf, readBuf;
    int deviceNumber;

#ifdef WOLFTPM_DEBUG_VERBOSE
    printf("Command size: %d\n", packet->pos);
    TPM2_PrintBin(packet->buf, packet->pos);
#endif

    rStatus = CyLibraryInit();
    if (rStatus != CY_SUCCESS) {
        printf("CYUSB: Cypress USB library init failed ERRNO=%d\n", rStatus);
        return rc;
    }

    rc = TPM2_CYUSB_FindDevice(&deviceNumber);
    if (rc != TPM_RC_SUCCESS || deviceNumber == TPM2_CYUSB_RC_NODEVICE) {
        printf("No matching UBS device found\n");
    }
    else {
        rStatus = CyOpen(deviceNumber, TPM2_CYUSB_INTERFACE, &handle);
        if (rStatus != CY_SUCCESS) {
            printf("CYUSB: Unable to open the UBS device ERRNO=%d\n", rStatus);
        }
        else {
            writeBuf.length = packet->pos;
            writeBuf.buffer = packet->buf;
            /* TODO: Confirm the Cypress library can safely use one buffer */
            readBuf.buffer = packet->buf;

            /* Send the TPM command over the Cypress USB channel */
            rStatus = CySpiReadWrite(handle, &readBuf, &writeBuf, 5000);
            printf("CYUSB: Unable to write to the TPM2.0 on USB ERRNO=%d\n", rStatus);

            /* The caller parses the TPM_Packet for correctness */
            if (readBuf.transferCount >= TPM2_HEADER_SIZE) {
               /* Enough bytes for a TPM response */
               packet->pos = readBuf.transferCount;
               rc = TPM_RC_SUCCESS;
            }
            CyClose(handle);
        }
    }

    CyLibraryExit();

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
