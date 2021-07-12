/* gpio.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef _GPIO_H_
#define _GPIO_H_

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(WOLFTPM_ST33) || defined(WOLFTPM_NUVOTON) || defined(WOLFTPM_AUTODETECT)
#define GPIO_NUM_MIN TPM_GPIO_A
#define GPIO_NUM_MAX TPM_GPIO_A+TPM_GPIO_COUNT-1 /* see wolftpm/tpm2.h */
#endif

#ifdef WOLFTPM_NUVOTON
/* Nuvoton GPIO Modes - only output */
#define NUVOTON_GPIO_MODE_PUSHPULL  1
#define NUVOTON_GPIO_MODE_OPENDRAIN 2
#define NUVOTON_GPIO_MODE_PULLUP    3
#define NUVOTON_GPIO_MODE_UNCONFIG  4 /* Not a real GPIO mode, deleting NV index */
#define NUVOTON_GPIO_MODE_MAX 4
#endif

int TPM2_GPIO_Config_Example(void* userCtx, int argc, char *argv[]);
int TPM2_GPIO_Read_Example(void* userCtx, int argc, char *argv[]);
int TPM2_GPIO_Set_Example(void* userCtx, int argc, char *argv[]);
int TPM2_GPIO_Nuvoton_Example(void* userCtx, int argc, char *argv[]);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* _GPIO_H_ */
