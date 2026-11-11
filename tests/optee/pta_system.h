/* pta_system.h
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

/* Host stand-in for OP-TEE's system pseudo trusted application interface.
 * Only the TA unique key derivation is used. */

#ifndef MOCK_PTA_SYSTEM_H
#define MOCK_PTA_SYSTEM_H

#define PTA_SYSTEM_UUID { 0x3a2f8978, 0x5dc0, 0x11e8, \
    { 0x9c, 0x2d, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc } }

#define PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY 1

#endif /* MOCK_PTA_SYSTEM_H */
