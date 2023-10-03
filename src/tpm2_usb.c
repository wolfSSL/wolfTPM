/* tpm2_usb.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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


#ifdef WOLFTPM_USB

#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_usb.h>



#define VID_CYPRESS  0x04B4u
#define PID_CYUSBSPI 0x0004u

#define CTRL_SET 0xC0u
#define CTRL_GET 0x40u

#define CY_CMD_SPI       0xCAu
#define CY_CMD_GPIO_SET  0xDBu
#define CY_SPI_WRITEREAD 0x03u

#define EP_OUT 0x01u
#define EP_IN  0x82u

#define SPI_TIMEOUT 1000
#define SPI_MAX_TRANSFER (4 + 64)

static int TPM2_USB_Init(TPM2_CTX* ctx)
{
    int ret;
    int nb_ifaces = 0;
    libusb_device *dev = NULL;
    struct libusb_config_descriptor *conf_desc = NULL;

    if (ctx->usbCtx.dev_ctx != NULL) {
        return 0; /* already initialized */
    }

    ret = libusb_init(&ctx->usbCtx.dev_ctx);
    if (ret == 0) {
        ctx->usbCtx.dev_handle = libusb_open_device_with_vid_pid(ctx->usbCtx.dev_ctx,
            VID_CYPRESS, PID_CYUSBSPI);
        if (ctx->usbCtx.dev_handle == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        dev = libusb_get_device(ctx->usbCtx.dev_handle);
        if (dev == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = libusb_get_config_descriptor(dev, 0, &conf_desc);
        if (ret == 0) {
            nb_ifaces = conf_desc->bNumInterfaces;
            if (nb_ifaces <= 0) {
                ret = -1;
            }
            libusb_free_config_descriptor(conf_desc);
        }
    }
    if (ret == 0) {
        ret = libusb_set_auto_detach_kernel_driver(ctx->usbCtx.dev_handle, 1);
    }
    if (ret == 0) {
        ret = libusb_claim_interface(ctx->usbCtx.dev_handle, 0);
    }

    ctx->usbCtx.spi_dma_buffer = libusb_dev_mem_alloc(ctx->usbCtx.dev_handle, SPI_MAX_TRANSFER);
    /* failure to allocate DMA, means we will use the buffer directly */

    if (ret != 0) {
        TPM2_USB_Cleanup(ctx);
    }
    return ret;
}


int TPM2_USB_SendCommand(TPM2_CTX* ctx, TPM2_Packet* packet)
{
    int ret;
    int act_len = 0;
    int retry = 0;
    int transferred = 0;
    int length;
    uint8_t* buffer;

    ret = TPM2_USB_Init(ctx);

    /* start transfer */
    if (ret == 0) {
        length = packet->pos;
        if (ctx->usbCtx.spi_dma_buffer != NULL && length < SPI_MAX_TRANSFER) {
            buffer = ctx->usbCtx.spi_dma_buffer;
            XMEMCPY(buffer, packet->buf, length);
        }
        else {
            buffer = packet->buf;
        }

        ret = libusb_control_transfer(ctx->usbCtx.dev_handle, CTRL_SET, CY_CMD_SPI,
            CY_SPI_WRITEREAD, length, NULL, 0, SPI_TIMEOUT);

        /* do send */
        while (ret == 0 && transferred < length) {
            ret = libusb_bulk_transfer(ctx->usbCtx.dev_handle, EP_OUT,
                ctx->usbCtx.spi_dma_buffer + transferred, length, &act_len, SPI_TIMEOUT);
            if (ret == 0) {
                transferred += act_len;
                length -= act_len;
            }
        }

        /* do receive */
        transferred = 0;
        length = packet->pos;
        while (ret == 0 && transferred < length) {
            ret = libusb_bulk_transfer(ctx->usbCtx.dev_handle, EP_IN,
                ctx->usbCtx.spi_dma_buffer + transferred, length, &act_len, SPI_TIMEOUT);
            if (ret != 0) {
                /* allow retry up to 5 times */
                if (retry++ > 5) {
                    ret = -1;
                    break;
                }
                continue;
            }
            transferred += act_len;
            length -= act_len;
        }
    }

    return ret;
}

int TPM2_USB_Cleanup(TPM2_CTX* ctx)
{
    if (ctx->usbCtx.dev_handle != NULL) {
        if (ctx->usbCtx.spi_dma_buffer != NULL) {
            libusb_dev_mem_free(ctx->usbCtx.dev_handle,
                ctx->usbCtx.spi_dma_buffer, SPI_MAX_TRANSFER);
        }

        libusb_release_interface(ctx->usbCtx.dev_handle, 0);
        libusb_close(ctx->usbCtx.dev_handle);
        ctx->usbCtx.dev_handle = NULL;
    }
    if (ctx->usbCtx.dev_ctx != NULL) {
        libusb_exit(ctx->usbCtx.dev_ctx);
        ctx->usbCtx.dev_ctx = NULL;
    }
    return 0;
}

#endif /* WOLFTPM_USB */
