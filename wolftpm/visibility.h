/* visibility.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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

/* Visibility control macros */

#ifndef WOLFTPM_VISIBILITY_H
#define WOLFTPM_VISIBILITY_H

/* WOLFTPM_API is used for the public API symbols.
        It either imports or exports (or does nothing for static builds)

   WOLFTPM_LOCAL is used for non-API symbols (private).
*/

#if defined(BUILDING_WOLFTPM)
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #ifdef WOLFTPM_DLL
            #define WOLFTPM_API __declspec(dllexport)
        #else
            #define WOLFTPM_API
        #endif
        #define WOLFTPM_LOCAL
    #elif defined(HAVE_VISIBILITY) && HAVE_VISIBILITY
        #define WOLFTPM_API   __attribute__ ((visibility("default")))
        #define WOLFTPM_LOCAL __attribute__ ((visibility("hidden")))
    #elif defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)
        #define WOLFTPM_API   __global
        #define WOLFTPM_LOCAL __hidden
    #else
        #define WOLFTPM_API
        #define WOLFTPM_LOCAL
    #endif /* HAVE_VISIBILITY */
#else /* BUILDING_WOLFTPM */
    #if defined(_MSC_VER) || defined(__MINGW32__) || defined(__CYGWIN__) || \
        defined(_WIN32_WCE)
        #ifdef WOLFTPM_DLL
            #define WOLFTPM_API __declspec(dllimport)
        #else
            #define WOLFTPM_API
        #endif
        #define WOLFTPM_LOCAL
    #else
        #define WOLFTPM_API
        #define WOLFTPM_LOCAL
    #endif
#endif /* BUILDING_WOLFTPM */

#endif /* WOLFTPM_VISIBILITY_H */
