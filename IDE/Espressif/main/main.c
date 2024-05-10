/* wolftpm test main.c
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

/* Espressif */
#include <esp_log.h>

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Reminder: settings.h pulls in user_settings.h; don't include it here. */
#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
    #ifndef WOLFSSL_ESPIDF
        #warning "Problem with wolfSSL user_settings."
        #warning "Check components/wolfssl/include"
    #endif
    #include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#else
    /* Define WOLFSSL_USER_SETTINGS project wide for settings.h to include   */
    /* wolfSSL user settings in ./components/wolfssl/include/user_settings.h */
    #error "Missing WOLFSSL_USER_SETTINGS in CMakeLists or Makefile:\
    CFLAGS +=-DWOLFSSL_USER_SETTINGS"
#endif

/* wolfTPM */
#ifdef WOLFTPM_USER_SETTINGS
    /* See wolfSSL user_settings.h for wolfTPM configuration */
#else
    #include <wolftpm/options.h>
#endif
#include <wolftpm/version.h>

/* project */
#include <examples/native/native_test.h>
#include "main.h"

#ifndef WOLFTPM_MAIN_TEST_ITERATIONS
    #define WOLFTPM_MAIN_TEST_ITERATIONS 1
#endif

static const char* const TAG = "wolfTPM main";

void app_main(void)
{
    char mydata[1024];
    int tests = WOLFTPM_MAIN_TEST_ITERATIONS;
    esp_err_t ret = 0;

#ifdef LIBWOLFTPM_VERSION_STRING
    ESP_LOGI(TAG, "Hello wolfTPM version %s!", LIBWOLFTPM_VERSION_STRING);
#else
    ESP_LOGI(TAG, "Hello wolfTPM!");
#endif

#ifdef HAVE_VERSION_EXTENDED_INFO
    ret = esp_ShowExtendedSystemInfo();
#endif

    do {
        ret += TPM2_Native_TestArgs(mydata, 0, NULL);
        if (tests > 1) {
            ESP_LOGW(TAG, "*************************************************");
            ESP_LOGW(TAG, "\n\n   Proceeding to Test #%d of %d\n\n",
                          WOLFTPM_MAIN_TEST_ITERATIONS - tests + 2,
                          WOLFTPM_MAIN_TEST_ITERATIONS);
            ESP_LOGW(TAG, "*************************************************");
            ESP_LOGI(TAG, "Waiting to start next test iteration...\n\n");
            vTaskDelay(5550);
        }
    } while (ret == 0 && (--tests > 0));

#ifdef WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE
    if (ret == 0) {
        ESP_LOGI(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Success!", ret));
    }
    else {
        ESP_LOGE(TAG, WOLFSSL_ESPIDF_VERBOSE_EXIT_MESSAGE("Failed!", ret));
    }
#elif defined(WOLFSSL_ESPIDF_EXIT_MESSAGE)
    ESP_LOGI(TAG, WOLFSSL_ESPIDF_EXIT_MESSAGE);
#else
    ESP_LOGI(TAG, "\n\nDone!"
                  "If running from idf.py monitor, press twice: Ctrl+]\n\n"
                  "WOLFSSL_COMPLETE\n" /* exit keyword for wolfssl_monitor.py */
            );
#endif
}
