/* packet_auth_tests.c
 *
 * Authorization-area accounting, with no TPM and no vendor build selected.
 *
 * TPM2_GetCmdAuthCount and TPM2_Packet_AppendAuth are general: every build
 * that uses an HMAC session goes through them. spdm_config_tests.c also
 * covers them, but only under the Infineon SPDM configuration, so a
 * regression in a plain build would go unnoticed.
 *
 * Both are WOLFTPM_LOCAL, so the library objects are linked directly rather
 * than through the shared library, as tests/include.am does elsewhere.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_wrap.h>
#include <wolftpm/tpm2_packet.h>

#include <stdio.h>

static int test_auth_count(void)
{
    WOLFTPM2_DEV dev;
    CmdInfo_t info;

    XMEMSET(&dev, 0, sizeof(dev));
    dev.ctx.session = dev.session;

    /* A required HMAC authorization occupies the slot that password or
     * policy authorization would use, and counts with no attribute set. */
    XMEMSET(&info, 0, sizeof(info));
    info.flags = CMD_FLAG_AUTH_USER1;
    dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 1)
        return 1;

    /* Without the auth flag the same session is not an auth session. */
    info.flags = 0;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 0)
        return 2;

    /* A further HMAC session still needs an attribute the command uses. */
    info.flags = CMD_FLAG_AUTH_USER1 | CMD_FLAG_ENC2;
    dev.session[0].sessionHandle = TPM_RS_PW;
    dev.session[1].sessionHandle = HMAC_SESSION_FIRST;
    dev.session[1].sessionAttributes = TPMA_SESSION_decrypt;
    if (TPM2_GetCmdAuthCount(&dev.ctx, &info) != 2)
        return 3;

    return 0;
}

static int test_hmac_auth_size(void)
{
    WOLFTPM2_DEV dev;
    CmdInfo_t info;
    TPM2_Packet packet;
    byte buf[256];
    int posSmallAuth, posLargeAuth;

    XMEMSET(&dev, 0, sizeof(dev));
    dev.ctx.session = dev.session;

    XMEMSET(&info, 0, sizeof(info));
    info.flags = CMD_FLAG_AUTH_USER1;
    dev.session[0].sessionHandle = HMAC_SESSION_FIRST;
    dev.session[0].authHash = TPM_ALG_SHA256;

    /* The HMAC reserved in the auth area is the size of the session hash,
     * not of the authorization value, so changing auth.size must not move
     * the packet position. */
    dev.session[0].auth.size = 4;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = (int)sizeof(buf);
    TPM2_Packet_AppendAuth(&packet, &dev.ctx, &info);
    posSmallAuth = packet.pos;

    dev.session[0].auth.size = 32;
    XMEMSET(&packet, 0, sizeof(packet));
    packet.buf = buf;
    packet.size = (int)sizeof(buf);
    TPM2_Packet_AppendAuth(&packet, &dev.ctx, &info);
    posLargeAuth = packet.pos;

    if (posSmallAuth <= 0)
        return 4;
    if (posSmallAuth != posLargeAuth)
        return 5;

    return 0;
}

int main(void)
{
    int rc;

    rc = test_auth_count();
    if (rc != 0) {
        printf("FAIL: command auth count (%d)\n", rc);
        return rc;
    }
    puts("PASS: command auth count with HMAC sessions");

    rc = test_hmac_auth_size();
    if (rc != 0) {
        printf("FAIL: HMAC auth area size (%d)\n", rc);
        return rc;
    }
    puts("PASS: HMAC auth area sized by the session hash");

    return 0;
}
