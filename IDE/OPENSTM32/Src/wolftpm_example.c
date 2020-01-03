/* wolftpm_example.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


#include "wolftpm_example.h"

/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/

/* UART definitions */
extern UART_HandleTypeDef huart4;
extern SPI_HandleTypeDef hspi1;


#ifdef WOLF_TPM2
    #include <examples/wrap/wrap_test.h>
#endif


/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

const char menu1[] = "\r\n"
    "\tt. WolfCrypt Test\r\n"
    "\tb. WolfCrypt Benchmark\r\n"
	"\tm. WolfCrypt TPM 2.0 Test\r\n";

/*****************************************************************************
 * Private functions
 ****************************************************************************/


/*****************************************************************************
 * Public functions
 ****************************************************************************/
void wolfTPMDemo(void const * argument)
{
    uint8_t buffer[2];
    func_args args;

    while (1) {
        printf("\r\n\t\t\t\tMENU\r\n");
        printf(menu1);
        printf("Please select one of the above options: ");

        HAL_UART_Receive(&huart4, buffer, sizeof(buffer), 5000);

        switch (buffer[0]) {

        case 't':
            XMEMSET(&args, 0, sizeof(args));
            printf("\nCrypt Test\n");
            wolfcrypt_test(&args);
            printf("Crypt Test: Return code %d\n", args.return_code);
            break;

        case 'b':
            XMEMSET(&args, 0, sizeof(args));
            printf("\nBenchmark Test\n");
            benchmark_test(&args);
            printf("Benchmark Test: Return code %d\n", args.return_code);
            break;

        case 'm':
			printf("\nTPM 2.0 Test\n");
#ifndef WOLFTPM2_NO_WRAPPER
			args.return_code = TPM2_Wrapper_Test(&hspi1);
#endif
			printf("TPM 2.0 Test: Return code %d\n", args.return_code);
			break;

        // All other cases go here
        default: printf("\r\nSelection out of range\r\n"); break;
        }
    }
}

extern RTC_HandleTypeDef hrtc;
double current_time()
{
	RTC_TimeTypeDef time;
	RTC_DateTypeDef date;
	uint32_t subsec;

	/* must get time and date here due to STM32 HW bug */
	HAL_RTC_GetTime(&hrtc, &time, FORMAT_BIN);
	HAL_RTC_GetDate(&hrtc, &date, FORMAT_BIN);
	subsec = (255 - time.SubSeconds) * 1000 / 255;

	(void)date;

	/* return seconds.milliseconds */
	return ((double)time.Hours * 24) +
		   ((double)time.Minutes * 60) +
			(double)time.Seconds +
		   ((double)subsec/1000);
}

