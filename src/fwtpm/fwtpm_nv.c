/* fwtpm_nv.c
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

/* fwTPM NV Storage — TLV Journal Format
 *
 * NV image layout:
 *   [FWTPM_NV_HEADER: 16 bytes]
 *   [TLV entry 1] [TLV entry 2] ... [TLV entry N]
 *   [0xFF... free space]
 *
 * Each TLV entry: [UINT16 tag][UINT16 length][byte value[length]]
 * Journal semantics: latest entry with same tag+key wins.
 * Compaction: on FWTPM_NV_Save(), writes only latest entries.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2_types.h>

#ifdef WOLFTPM_FWTPM

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_nv.h>

#include <stdio.h>
#include <string.h>

/* TLV header size: tag(2) + length(2) */
#define TLV_HDR_SIZE  4

/* ========================================================================= */
/* File-based NV backend                                                     */
/* ========================================================================= */

#ifndef NO_FILESYSTEM

static int FwNvFileRead(void* ctx, word32 offset, byte* buf, word32 size)
{
    const char* path = (const char*)ctx;
    FILE* f;
    int ret;

    f = fopen(path, "rb");
    if (f == NULL) {
        return TPM_RC_FAILURE;
    }

    if (fseek(f, (long)offset, SEEK_SET) != 0) {
        fclose(f);
        return TPM_RC_FAILURE;
    }

    ret = (int)fread(buf, 1, size, f);
    fclose(f);

    if (ret != (int)size) {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

static int FwNvFileWrite(void* ctx, word32 offset, const byte* buf,
    word32 size)
{
    const char* path = (const char*)ctx;
    FILE* f;
    int ret;
    long fileSize;

    /* Open for read+write if exists, otherwise create */
    f = fopen(path, "r+b");
    if (f == NULL) {
        f = fopen(path, "wb");
        if (f == NULL) {
            return TPM_RC_FAILURE;
        }
    }

    /* If writing past current end, extend with zeros */
    fseek(f, 0, SEEK_END);
    fileSize = ftell(f);
    if ((long)offset > fileSize) {
        byte zero = 0;
        long i;
        for (i = fileSize; i < (long)offset; i++) {
            if (fwrite(&zero, 1, 1, f) != 1) {
                fclose(f);
                return TPM_RC_FAILURE;
            }
        }
    }

    if (fseek(f, (long)offset, SEEK_SET) != 0) {
        fclose(f);
        return TPM_RC_FAILURE;
    }

    ret = (int)fwrite(buf, 1, size, f);
    fclose(f);

    if (ret != (int)size) {
        return TPM_RC_FAILURE;
    }

    return TPM_RC_SUCCESS;
}

static int FwNvFileErase(void* ctx, word32 offset, word32 size)
{
    const char* path = (const char*)ctx;
    FILE* f;
    (void)offset;
    (void)size;

    /* For file-based backend, truncate the file */
    f = fopen(path, "wb");
    if (f == NULL) {
        return TPM_RC_FAILURE;
    }
    fclose(f);
    return TPM_RC_SUCCESS;
}

/* Default file-based HAL */
static FWTPM_NV_HAL fwNvDefaultHal = {
    FwNvFileRead,
    FwNvFileWrite,
    FwNvFileErase,
    (void*)FWTPM_NV_FILE,
    FWTPM_NV_MAX_SIZE
};

#endif /* !NO_FILESYSTEM */

/* ========================================================================= */
/* TLV Marshal Helpers                                                       */
/* ========================================================================= */

static int FwNvMarshalU16(byte* buf, word32* pos, word32 maxSz, UINT16 val)
{
    if (*pos + 2 > maxSz) {
        return TPM_RC_FAILURE;
    }
    FwStoreU16LE(buf + *pos, val);
    *pos += 2;
    return 0;
}

static int FwNvMarshalU32(byte* buf, word32* pos, word32 maxSz, UINT32 val)
{
    if (*pos + 4 > maxSz) {
        return TPM_RC_FAILURE;
    }
    FwStoreU32LE(buf + *pos, val);
    *pos += 4;
    return 0;
}

static int FwNvMarshalBytes(byte* buf, word32* pos, word32 maxSz,
    const byte* data, word32 len)
{
    if (*pos + len > maxSz) {
        return TPM_RC_FAILURE;
    }
    if (len > 0) {
        XMEMCPY(buf + *pos, data, len);
    }
    *pos += len;
    return 0;
}

static int FwNvMarshalU8(byte* buf, word32* pos, word32 maxSz, UINT8 val)
{
    if (*pos + 1 > maxSz) {
        return TPM_RC_FAILURE;
    }
    buf[*pos] = val;
    *pos += 1;
    return 0;
}

static int FwNvUnmarshalU8(const byte* buf, word32* pos, word32 maxSz,
    UINT8* val)
{
    if (*pos + 1 > maxSz) {
        return TPM_RC_FAILURE;
    }
    *val = buf[*pos];
    *pos += 1;
    return 0;
}

static int FwNvUnmarshalU16(const byte* buf, word32* pos, word32 maxSz,
    UINT16* val)
{
    if (*pos + 2 > maxSz) {
        return TPM_RC_FAILURE;
    }
    *val = FwLoadU16LE(buf + *pos);
    *pos += 2;
    return 0;
}

static int FwNvUnmarshalU32(const byte* buf, word32* pos, word32 maxSz,
    UINT32* val)
{
    if (*pos + 4 > maxSz) {
        return TPM_RC_FAILURE;
    }
    *val = FwLoadU32LE(buf + *pos);
    *pos += 4;
    return 0;
}

static int FwNvUnmarshalBytes(const byte* buf, word32* pos, word32 maxSz,
    byte* data, word32 len)
{
    if (*pos + len > maxSz) {
        return TPM_RC_FAILURE;
    }
    if (len > 0) {
        XMEMCPY(data, buf + *pos, len);
    }
    *pos += len;
    return 0;
}

/* Marshal TPM2B_AUTH: UINT16 size + byte[size] */
static int FwNvMarshalAuth(byte* buf, word32* pos, word32 maxSz,
    const TPM2B_AUTH* auth)
{
    int rc;
    UINT16 sz = auth->size;
    if (sz > sizeof(auth->buffer)) {
        sz = 0;
    }
    rc = FwNvMarshalU16(buf, pos, maxSz, sz);
    if (rc == 0 && sz > 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, auth->buffer, sz);
    }
    return rc;
}

static int FwNvUnmarshalAuth(const byte* buf, word32* pos, word32 maxSz,
    TPM2B_AUTH* auth)
{
    int rc;
    rc = FwNvUnmarshalU16(buf, pos, maxSz, &auth->size);
    if (rc == 0) {
        if (auth->size > sizeof(auth->buffer)) {
            auth->size = 0;
            return TPM_RC_FAILURE;
        }
        if (auth->size > 0) {
            rc = FwNvUnmarshalBytes(buf, pos, maxSz,
                auth->buffer, auth->size);
        }
    }
    return rc;
}

/* Marshal TPM2B_DIGEST: same as Auth */
static int FwNvMarshalDigest(byte* buf, word32* pos, word32 maxSz,
    const TPM2B_DIGEST* digest)
{
    return FwNvMarshalAuth(buf, pos, maxSz, (const TPM2B_AUTH*)digest);
}

static int FwNvUnmarshalDigest(const byte* buf, word32* pos, word32 maxSz,
    TPM2B_DIGEST* digest)
{
    return FwNvUnmarshalAuth(buf, pos, maxSz, (TPM2B_AUTH*)digest);
}

/* Marshal TPMT_PUBLIC using TPM2_Packet infrastructure.
 * Uses TPM2_Packet_AppendPublic which writes a BE size prefix + public area. */
static int FwNvMarshalPublic(byte* buf, word32* pos, word32 maxSz,
    TPMT_PUBLIC* pub)
{
    TPM2_Packet pkt;
    TPM2B_PUBLIC pub2b;

    XMEMSET(&pkt, 0, sizeof(pkt));
    pkt.buf = buf + *pos;
    pkt.pos = 0;
    pkt.size = (int)(maxSz - *pos);

    XMEMCPY(&pub2b.publicArea, pub, sizeof(TPMT_PUBLIC));
    TPM2_Packet_AppendPublic(&pkt, &pub2b);

    if (pkt.pos <= 0 || (word32)pkt.pos > (maxSz - *pos)) {
        return TPM_RC_FAILURE;
    }
    *pos += pkt.pos;
    return 0;
}

static int FwNvUnmarshalPublic(const byte* buf, word32* pos, word32 maxSz,
    TPMT_PUBLIC* pub)
{
    TPM2_Packet pkt;
    TPM2B_PUBLIC pub2b;

    XMEMSET(&pkt, 0, sizeof(pkt));
    pkt.buf = (byte*)(buf + *pos);
    pkt.pos = 0;
    pkt.size = (int)(maxSz - *pos);

    TPM2_Packet_ParsePublic(&pkt, &pub2b);

    if (pkt.pos <= 0 || (word32)pkt.pos > (maxSz - *pos)) {
        return TPM_RC_FAILURE;
    }
    XMEMCPY(pub, &pub2b.publicArea, sizeof(TPMT_PUBLIC));

    *pos += pkt.pos;
    return 0;
}

/* Marshal TPM2B_NAME: UINT16 size + byte[size] */
static int FwNvMarshalName(byte* buf, word32* pos, word32 maxSz,
    const TPM2B_NAME* name)
{
    int rc;
    UINT16 sz = name->size;
    if (sz > sizeof(name->name)) {
        sz = 0;
    }
    rc = FwNvMarshalU16(buf, pos, maxSz, sz);
    if (rc == 0 && sz > 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, name->name, sz);
    }
    return rc;
}

static int FwNvUnmarshalName(const byte* buf, word32* pos, word32 maxSz,
    TPM2B_NAME* name)
{
    int rc;
    rc = FwNvUnmarshalU16(buf, pos, maxSz, &name->size);
    if (rc == 0) {
        if (name->size > sizeof(name->name)) {
            name->size = 0;
            return TPM_RC_FAILURE;
        }
        if (name->size > 0) {
            rc = FwNvUnmarshalBytes(buf, pos, maxSz,
                name->name, name->size);
        }
    }
    return rc;
}

/* Marshal TPMS_NV_PUBLIC manually (no packet function exists) */
static int FwNvMarshalNvPublic(byte* buf, word32* pos, word32 maxSz,
    const TPMS_NV_PUBLIC* nvPub)
{
    int rc;
    rc = FwNvMarshalU32(buf, pos, maxSz, nvPub->nvIndex);
    if (rc == 0) {
        rc = FwNvMarshalU16(buf, pos, maxSz, nvPub->nameAlg);
    }
    if (rc == 0) {
        rc = FwNvMarshalU32(buf, pos, maxSz, nvPub->attributes);
    }
    if (rc == 0) {
        rc = FwNvMarshalDigest(buf, pos, maxSz, &nvPub->authPolicy);
    }
    if (rc == 0) {
        rc = FwNvMarshalU16(buf, pos, maxSz, nvPub->dataSize);
    }
    return rc;
}

static int FwNvUnmarshalNvPublic(const byte* buf, word32* pos, word32 maxSz,
    TPMS_NV_PUBLIC* nvPub)
{
    int rc;
    rc = FwNvUnmarshalU32(buf, pos, maxSz, &nvPub->nvIndex);
    if (rc == 0) {
        rc = FwNvUnmarshalU16(buf, pos, maxSz, &nvPub->nameAlg);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU32(buf, pos, maxSz, &nvPub->attributes);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalDigest(buf, pos, maxSz, &nvPub->authPolicy);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU16(buf, pos, maxSz, &nvPub->dataSize);
    }
    return rc;
}

/* ========================================================================= */
/* Entry-level marshal/unmarshal                                             */
/* ========================================================================= */

/* Marshal FWTPM_NvIndex → value bytes (variable length) */
static int FwNvMarshalNvIndex(byte* buf, word32* pos, word32 maxSz,
    const FWTPM_NvIndex* nv)
{
    int rc;
    UINT16 dataLen;

    /* nvHandle is embedded in nvPublic.nvIndex */
    rc = FwNvMarshalNvPublic(buf, pos, maxSz, &nv->nvPublic);
    if (rc == 0) {
        rc = FwNvMarshalAuth(buf, pos, maxSz, &nv->authValue);
    }
    if (rc == 0) {
        rc = FwNvMarshalU8(buf, pos, maxSz, (UINT8)nv->written);
    }
    /* Only marshal actual data bytes, not full FWTPM_MAX_NV_DATA */
    dataLen = nv->nvPublic.dataSize;
    if (dataLen > FWTPM_MAX_NV_DATA) {
        dataLen = FWTPM_MAX_NV_DATA;
    }
    if (rc == 0) {
        rc = FwNvMarshalU16(buf, pos, maxSz, dataLen);
    }
    if (rc == 0 && dataLen > 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, nv->data, dataLen);
    }
    return rc;
}

static int FwNvUnmarshalNvIndex(const byte* buf, word32* pos, word32 maxSz,
    FWTPM_NvIndex* nv)
{
    int rc;
    UINT16 dataLen;
    UINT8 written = 0;

    XMEMSET(nv, 0, sizeof(FWTPM_NvIndex));
    nv->inUse = 1;

    rc = FwNvUnmarshalNvPublic(buf, pos, maxSz, &nv->nvPublic);
    if (rc == 0) {
        rc = FwNvUnmarshalAuth(buf, pos, maxSz, &nv->authValue);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU8(buf, pos, maxSz, &written);
        nv->written = (int)written;
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU16(buf, pos, maxSz, &dataLen);
    }
    if (rc == 0) {
        if (dataLen > FWTPM_MAX_NV_DATA) {
            return TPM_RC_FAILURE;
        }
        if (dataLen > 0) {
            rc = FwNvUnmarshalBytes(buf, pos, maxSz, nv->data, dataLen);
        }
    }
    return rc;
}

/* Marshal FWTPM_Object → value bytes */
static int FwNvMarshalObject(byte* buf, word32* pos, word32 maxSz,
    const FWTPM_Object* obj)
{
    int rc;
    UINT16 privSz;

    rc = FwNvMarshalU32(buf, pos, maxSz, obj->handle);
    if (rc == 0) {
        rc = FwNvMarshalPublic(buf, pos, maxSz, (TPMT_PUBLIC*)&obj->pub);
    }
    if (rc == 0) {
        rc = FwNvMarshalAuth(buf, pos, maxSz, &obj->authValue);
    }
    /* Only marshal actual private key bytes */
    privSz = (UINT16)obj->privKeySize;
    if (privSz > FWTPM_MAX_PRIVKEY_DER) {
        privSz = 0;
    }
    if (rc == 0) {
        rc = FwNvMarshalU16(buf, pos, maxSz, privSz);
    }
    if (rc == 0 && privSz > 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, obj->privKey, privSz);
    }
    if (rc == 0) {
        rc = FwNvMarshalName(buf, pos, maxSz, &obj->name);
    }
    return rc;
}

static int FwNvUnmarshalObject(const byte* buf, word32* pos, word32 maxSz,
    FWTPM_Object* obj)
{
    int rc;
    UINT16 privSz;

    XMEMSET(obj, 0, sizeof(FWTPM_Object));

    rc = FwNvUnmarshalU32(buf, pos, maxSz, &obj->handle);
    if (rc == 0) {
        rc = FwNvUnmarshalPublic(buf, pos, maxSz, &obj->pub);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalAuth(buf, pos, maxSz, &obj->authValue);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU16(buf, pos, maxSz, &privSz);
    }
    if (rc == 0) {
        if (privSz > FWTPM_MAX_PRIVKEY_DER) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        obj->privKeySize = (int)privSz;
        if (privSz > 0) {
            rc = FwNvUnmarshalBytes(buf, pos, maxSz, obj->privKey, privSz);
        }
    }
    if (rc == 0) {
        rc = FwNvUnmarshalName(buf, pos, maxSz, &obj->name);
    }
    if (rc == 0) {
        obj->used = 1;
    }
    return rc;
}

/* Marshal FWTPM_PrimaryCache → value bytes */
static int FwNvMarshalPrimaryCache(byte* buf, word32* pos, word32 maxSz,
    const FWTPM_PrimaryCache* cache)
{
    int rc;
    UINT16 privSz;

    rc = FwNvMarshalU32(buf, pos, maxSz, cache->hierarchy);
    if (rc == 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, cache->templateHash,
            WC_SHA256_DIGEST_SIZE);
    }
    if (rc == 0) {
        rc = FwNvMarshalPublic(buf, pos, maxSz, (TPMT_PUBLIC*)&cache->pub);
    }
    privSz = (UINT16)cache->privKeySize;
    if (privSz > FWTPM_MAX_PRIVKEY_DER) {
        privSz = 0;
    }
    if (rc == 0) {
        rc = FwNvMarshalU16(buf, pos, maxSz, privSz);
    }
    if (rc == 0 && privSz > 0) {
        rc = FwNvMarshalBytes(buf, pos, maxSz, cache->privKey, privSz);
    }
    return rc;
}

static int FwNvUnmarshalPrimaryCache(const byte* buf, word32* pos,
    word32 maxSz, FWTPM_PrimaryCache* cache)
{
    int rc;
    UINT16 privSz;

    XMEMSET(cache, 0, sizeof(FWTPM_PrimaryCache));

    rc = FwNvUnmarshalU32(buf, pos, maxSz, &cache->hierarchy);
    if (rc == 0) {
        rc = FwNvUnmarshalBytes(buf, pos, maxSz, cache->templateHash,
            WC_SHA256_DIGEST_SIZE);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalPublic(buf, pos, maxSz, &cache->pub);
    }
    if (rc == 0) {
        rc = FwNvUnmarshalU16(buf, pos, maxSz, &privSz);
    }
    if (rc == 0) {
        if (privSz > FWTPM_MAX_PRIVKEY_DER) {
            rc = TPM_RC_FAILURE;
        }
    }
    if (rc == 0) {
        cache->privKeySize = (int)privSz;
        if (privSz > 0) {
            rc = FwNvUnmarshalBytes(buf, pos, maxSz, cache->privKey, privSz);
        }
    }
    if (rc == 0) {
        cache->used = 1;
    }
    return rc;
}

/* ========================================================================= */
/* Journal Operations                                                        */
/* ========================================================================= */

/* Write NV header at offset 0 */
static int FwNvWriteHeader(FWTPM_CTX* ctx)
{
    byte hdr[sizeof(FWTPM_NV_HEADER)]; /* 4 x UINT32 = 16 bytes */
    FWTPM_NV_HAL* hal = &ctx->nvHal;

    FwStoreU32LE(hdr + 0,  FWTPM_NV_MAGIC);
    FwStoreU32LE(hdr + 4,  FWTPM_NV_VERSION);
    FwStoreU32LE(hdr + 8,  ctx->nvWritePos);
    FwStoreU32LE(hdr + 12, hal->maxSize);

    return hal->write(hal->ctx, 0, hdr, sizeof(hdr));
}

/* Append a single TLV entry to the journal */
static int FwNvAppendEntry(FWTPM_CTX* ctx, UINT16 tag,
    const byte* value, UINT16 valueLen)
{
    FWTPM_NV_HAL* hal = &ctx->nvHal;
    word32 entrySize = TLV_HDR_SIZE + valueLen;
    byte tlvHdr[TLV_HDR_SIZE];
    int rc;

    if (hal->write == NULL) {
        return TPM_RC_FAILURE;
    }

    /* Check if journal has space */
    if (ctx->nvWritePos + entrySize > hal->maxSize) {
        /* If already compacting, NV is genuinely full */
        if (ctx->nvCompacting) {
            return TPM_RC_NV_SPACE;
        }
        /* Compact and retry */
        rc = FWTPM_NV_Save(ctx);
        if (rc != TPM_RC_SUCCESS) {
            return rc;
        }
        /* After compaction, check again */
        if (ctx->nvWritePos + entrySize > hal->maxSize) {
            return TPM_RC_NV_SPACE;
        }
    }

    /* Write TLV header */
    FwStoreU16LE(tlvHdr, tag);
    FwStoreU16LE(tlvHdr + 2, valueLen);

    rc = hal->write(hal->ctx, ctx->nvWritePos, tlvHdr, TLV_HDR_SIZE);
    if (rc == TPM_RC_SUCCESS && valueLen > 0) {
        rc = hal->write(hal->ctx, ctx->nvWritePos + TLV_HDR_SIZE,
            value, valueLen);
    }
    if (rc == TPM_RC_SUCCESS) {
        ctx->nvWritePos += entrySize;
        /* Update header with new writePos */
        rc = FwNvWriteHeader(ctx);
    }
    return rc;
}

/* ========================================================================= */
/* Journal Load (Init)                                                       */
/* ========================================================================= */

/* Find NV index slot by handle, or allocate empty slot */
static int FwNvFindOrAllocNvSlot(FWTPM_CTX* ctx, UINT32 nvHandle)
{
    int i;
    int freeSlot = -1;

    for (i = 0; i < FWTPM_MAX_NV_INDICES; i++) {
        if (ctx->nvIndices[i].inUse &&
            ctx->nvIndices[i].nvPublic.nvIndex == nvHandle) {
            return i;
        }
        if (!ctx->nvIndices[i].inUse && freeSlot < 0) {
            freeSlot = i;
        }
    }
    return freeSlot;
}

/* Find persistent object slot by handle, or allocate empty slot */
static int FwNvFindOrAllocPersSlot(FWTPM_CTX* ctx, UINT32 handle)
{
    int i;
    int freeSlot = -1;

    for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
        if (ctx->persistent[i].used &&
            ctx->persistent[i].handle == handle) {
            return i;
        }
        if (!ctx->persistent[i].used && freeSlot < 0) {
            freeSlot = i;
        }
    }
    return freeSlot;
}

/* Find primary cache slot by hierarchy + templateHash, or allocate */
static int FwNvFindOrAllocCacheSlot(FWTPM_CTX* ctx, UINT32 hierarchy,
    const byte* templateHash)
{
    int i;
    int freeSlot = -1;

    for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE; i++) {
        if (ctx->primaryCache[i].used &&
            ctx->primaryCache[i].hierarchy == hierarchy &&
            XMEMCMP(ctx->primaryCache[i].templateHash, templateHash,
                WC_SHA256_DIGEST_SIZE) == 0) {
            return i;
        }
        if (!ctx->primaryCache[i].used && freeSlot < 0) {
            freeSlot = i;
        }
    }
    return freeSlot;
}

/* Process a single TLV entry during journal scan */
static int FwNvProcessEntry(FWTPM_CTX* ctx, UINT16 tag,
    const byte* value, UINT16 valueLen)
{
    word32 vPos = 0;
    word32 vMax = (word32)valueLen;

    switch (tag) {
        case FWTPM_NV_TAG_OWNER_SEED:
            if (valueLen >= FWTPM_SEED_SIZE) {
                XMEMCPY(ctx->ownerSeed, value, FWTPM_SEED_SIZE);
            }
            break;

        case FWTPM_NV_TAG_ENDORSEMENT_SEED:
            if (valueLen >= FWTPM_SEED_SIZE) {
                XMEMCPY(ctx->endorsementSeed, value, FWTPM_SEED_SIZE);
            }
            break;

        case FWTPM_NV_TAG_PLATFORM_SEED:
            if (valueLen >= FWTPM_SEED_SIZE) {
                XMEMCPY(ctx->platformSeed, value, FWTPM_SEED_SIZE);
            }
            break;

        case FWTPM_NV_TAG_OWNER_AUTH:
            FwNvUnmarshalAuth(value, &vPos, vMax, &ctx->ownerAuth);
            break;

        case FWTPM_NV_TAG_ENDORSEMENT_AUTH:
            FwNvUnmarshalAuth(value, &vPos, vMax, &ctx->endorsementAuth);
            break;

        case FWTPM_NV_TAG_PLATFORM_AUTH:
            FwNvUnmarshalAuth(value, &vPos, vMax, &ctx->platformAuth);
            break;

        case FWTPM_NV_TAG_LOCKOUT_AUTH:
            FwNvUnmarshalAuth(value, &vPos, vMax, &ctx->lockoutAuth);
            break;

        case FWTPM_NV_TAG_PCR_STATE:
            if (valueLen >= (word32)sizeof(ctx->pcrDigest) + 4) {
                XMEMCPY(ctx->pcrDigest, value, sizeof(ctx->pcrDigest));
                vPos = (word32)sizeof(ctx->pcrDigest);
                FwNvUnmarshalU32(value, &vPos, vMax,
                    &ctx->pcrUpdateCounter);
            }
            break;

        case FWTPM_NV_TAG_PCR_AUTH: {
            int idx;
            UINT8 allocBanks = FWTPM_PCR_ALLOC_DEFAULT;
            FwNvUnmarshalU8(value, &vPos, vMax, &allocBanks);
            ctx->pcrAllocatedBanks = allocBanks;
            for (idx = 0; idx < IMPLEMENTATION_PCR && vPos < vMax; idx++) {
                FwNvUnmarshalAuth(value, &vPos, vMax, &ctx->pcrAuth[idx]);
                FwNvUnmarshalDigest(value, &vPos, vMax,
                    &ctx->pcrPolicy[idx]);
                FwNvUnmarshalU16(value, &vPos, vMax,
                    &ctx->pcrPolicyAlg[idx]);
            }
            break;
        }

        case FWTPM_NV_TAG_FLAGS: {
            UINT8 flags8 = 0;
            FwNvUnmarshalU8(value, &vPos, vMax, &flags8);
            ctx->disableClear = (flags8 & 0x01) ? 1 : 0;
        #ifndef FWTPM_NO_DA
            FwNvUnmarshalU32(value, &vPos, vMax, &ctx->daMaxTries);
            FwNvUnmarshalU32(value, &vPos, vMax, &ctx->daRecoveryTime);
            FwNvUnmarshalU32(value, &vPos, vMax, &ctx->daLockoutRecovery);
            ctx->daFailedTries = 0; /* volatile - reset on load */
        #endif
            break;
        }

        case FWTPM_NV_TAG_CLOCK: {
            UINT32 lo = 0, hi = 0;
            FwNvUnmarshalU32(value, &vPos, vMax, &lo);
            FwNvUnmarshalU32(value, &vPos, vMax, &hi);
            ctx->clockOffset = (UINT64)lo | ((UINT64)hi << 32);
            break;
        }

        case FWTPM_NV_TAG_HIERARCHY_POLICY: {
            UINT32 hier = 0;
            UINT16 alg = 0;
            TPM2B_DIGEST policy;
            XMEMSET(&policy, 0, sizeof(policy));
            FwNvUnmarshalU32(value, &vPos, vMax, &hier);
            FwNvUnmarshalU16(value, &vPos, vMax, &alg);
            FwNvUnmarshalDigest(value, &vPos, vMax, &policy);
            switch (hier) {
                case TPM_RH_OWNER:
                    XMEMCPY(&ctx->ownerPolicy, &policy,
                        sizeof(TPM2B_DIGEST));
                    ctx->ownerPolicyAlg = alg;
                    break;
                case TPM_RH_ENDORSEMENT:
                    XMEMCPY(&ctx->endorsementPolicy, &policy,
                        sizeof(TPM2B_DIGEST));
                    ctx->endorsementPolicyAlg = alg;
                    break;
                case TPM_RH_PLATFORM:
                    XMEMCPY(&ctx->platformPolicy, &policy,
                        sizeof(TPM2B_DIGEST));
                    ctx->platformPolicyAlg = alg;
                    break;
                case TPM_RH_LOCKOUT:
                    XMEMCPY(&ctx->lockoutPolicy, &policy,
                        sizeof(TPM2B_DIGEST));
                    ctx->lockoutPolicyAlg = alg;
                    break;
            }
            break;
        }

        case FWTPM_NV_TAG_NV_INDEX: {
            FWTPM_NvIndex nv;
            int slot;
            if (FwNvUnmarshalNvIndex(value, &vPos, vMax, &nv) == 0) {
                slot = FwNvFindOrAllocNvSlot(ctx, nv.nvPublic.nvIndex);
                if (slot >= 0) {
                    XMEMCPY(&ctx->nvIndices[slot], &nv,
                        sizeof(FWTPM_NvIndex));
                }
                else {
                    WOLFSSL_MSG("fwTPM NV: no free NV slot, entry dropped");
                }
            }
            break;
        }

        case FWTPM_NV_TAG_NV_INDEX_DEL: {
            UINT32 nvHandle = 0;
            int i;
            FwNvUnmarshalU32(value, &vPos, vMax, &nvHandle);
            for (i = 0; i < FWTPM_MAX_NV_INDICES; i++) {
                if (ctx->nvIndices[i].inUse &&
                    ctx->nvIndices[i].nvPublic.nvIndex == nvHandle) {
                    XMEMSET(&ctx->nvIndices[i], 0, sizeof(FWTPM_NvIndex));
                    break;
                }
            }
            break;
        }

        case FWTPM_NV_TAG_PERSISTENT: {
            FWTPM_Object obj;
            int slot;
            if (FwNvUnmarshalObject(value, &vPos, vMax, &obj) == 0) {
                slot = FwNvFindOrAllocPersSlot(ctx, obj.handle);
                if (slot >= 0) {
                    XMEMCPY(&ctx->persistent[slot], &obj,
                        sizeof(FWTPM_Object));
                }
            }
            break;
        }

        case FWTPM_NV_TAG_PERSISTENT_DEL: {
            UINT32 handle = 0;
            int i;
            FwNvUnmarshalU32(value, &vPos, vMax, &handle);
            for (i = 0; i < FWTPM_MAX_PERSISTENT; i++) {
                if (ctx->persistent[i].used &&
                    ctx->persistent[i].handle == handle) {
                    XMEMSET(&ctx->persistent[i], 0, sizeof(FWTPM_Object));
                    break;
                }
            }
            break;
        }

        case FWTPM_NV_TAG_PRIMARY_CACHE: {
            FWTPM_PrimaryCache cache;
            int slot;
            if (FwNvUnmarshalPrimaryCache(value, &vPos, vMax, &cache) == 0) {
                slot = FwNvFindOrAllocCacheSlot(ctx, cache.hierarchy,
                    cache.templateHash);
                if (slot >= 0) {
                    XMEMCPY(&ctx->primaryCache[slot], &cache,
                        sizeof(FWTPM_PrimaryCache));
                }
            }
            break;
        }

        case FWTPM_NV_TAG_PRIMARY_CACHE_DEL: {
            UINT32 hierarchy = 0;
            byte tmplHash[WC_SHA256_DIGEST_SIZE];
            int i;
            FwNvUnmarshalU32(value, &vPos, vMax, &hierarchy);
            if (vPos + WC_SHA256_DIGEST_SIZE <= vMax) {
                FwNvUnmarshalBytes(value, &vPos, vMax, tmplHash,
                    WC_SHA256_DIGEST_SIZE);
                for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE; i++) {
                    if (ctx->primaryCache[i].used &&
                        ctx->primaryCache[i].hierarchy == hierarchy &&
                        XMEMCMP(ctx->primaryCache[i].templateHash, tmplHash,
                            WC_SHA256_DIGEST_SIZE) == 0) {
                        XMEMSET(&ctx->primaryCache[i], 0,
                            sizeof(FWTPM_PrimaryCache));
                        break;
                    }
                }
            }
            break;
        }

        default:
            /* Unknown tag - skip */
            break;
    }

    return 0;
}

/* ========================================================================= */
/* Public API                                                                */
/* ========================================================================= */

int FWTPM_NV_SetHAL(FWTPM_CTX* ctx, FWTPM_NV_HAL* hal)
{
    if (ctx == NULL || hal == NULL) {
        return BAD_FUNC_ARG;
    }
    XMEMCPY(&ctx->nvHal, hal, sizeof(FWTPM_NV_HAL));
    return TPM_RC_SUCCESS;
}

int FWTPM_NV_Init(FWTPM_CTX* ctx)
{
    int rc;
    FWTPM_NV_HEADER hdr;
    byte hdrBuf[sizeof(FWTPM_NV_HEADER)];
    FWTPM_NV_HAL* hal;
    word32 pos;
    byte tlvHdr[TLV_HDR_SIZE];
    byte* valueBuf = NULL;
    word32 valueBufSz = FWTPM_NV_MAX_ENTRY;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Use custom HAL if set, otherwise default file-based */
    if (ctx->nvHal.read != NULL && ctx->nvHal.write != NULL) {
        hal = &ctx->nvHal;
    }
#ifndef NO_FILESYSTEM
    else {
        hal = &fwNvDefaultHal;
        XMEMCPY(&ctx->nvHal, hal, sizeof(FWTPM_NV_HAL));
    }
#else
    else {
        return BAD_FUNC_ARG; /* No NV HAL registered and no filesystem */
    }
#endif

    /* Allocate value read buffer */
    valueBuf = (byte*)XMALLOC(valueBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (valueBuf == NULL) {
        return TPM_RC_MEMORY;
    }

    /* Try to read existing NV header */
    XMEMSET(hdrBuf, 0, sizeof(hdrBuf));
    rc = hal->read(hal->ctx, 0, hdrBuf, sizeof(hdrBuf));
    if (rc == TPM_RC_SUCCESS) {
        hdr.magic    = FwLoadU32LE(hdrBuf + 0);
        hdr.version  = FwLoadU32LE(hdrBuf + 4);
        hdr.writePos = FwLoadU32LE(hdrBuf + 8);
        hdr.maxSize  = FwLoadU32LE(hdrBuf + 12);
    }

    if (rc == TPM_RC_SUCCESS &&
        hdr.magic == FWTPM_NV_MAGIC &&
        hdr.version == FWTPM_NV_VERSION) {
        /* Validate writePos against HAL bounds before using it */
        if (hdr.writePos < sizeof(FWTPM_NV_HEADER) ||
            hdr.writePos > hal->maxSize) {
            /* Corrupt — treat as uninitialized, will generate fresh state */
            rc = TPM_RC_NV_UNINITIALIZED;
        }
    }
    if (rc == TPM_RC_SUCCESS &&
        hdr.magic == FWTPM_NV_MAGIC &&
        hdr.version == FWTPM_NV_VERSION) {
        /* Valid v3 TLV journal — scan entries */
        ctx->nvWritePos = hdr.writePos;

        pos = (word32)sizeof(FWTPM_NV_HEADER);
        while (pos + TLV_HDR_SIZE <= ctx->nvWritePos) {
            UINT16 tag, len;

            rc = hal->read(hal->ctx, pos, tlvHdr, TLV_HDR_SIZE);
            if (rc != TPM_RC_SUCCESS) {
                break;
            }

            tag = FwLoadU16LE(tlvHdr);
            len = FwLoadU16LE(tlvHdr + 2);

            /* Check for free space marker (end of journal) */
            if (tag == FWTPM_NV_TAG_FREE) {
                break;
            }

            /* Validate entry bounds */
            if (pos + TLV_HDR_SIZE + len > ctx->nvWritePos) {
                break; /* Truncated entry - stop here */
            }

            /* Read value and dynamically expand buffer if needed */
            if (len > valueBufSz) {
                byte* newBuf;
                newBuf = (byte*)XMALLOC(len, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (newBuf == NULL) {
                    break;
                }
                XFREE(valueBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                valueBuf = newBuf;
                valueBufSz = len;
            }

            if (len > 0) {
                rc = hal->read(hal->ctx, pos + TLV_HDR_SIZE,
                    valueBuf, len);
                if (rc != TPM_RC_SUCCESS) {
                    break;
                }
            }

            FwNvProcessEntry(ctx, tag, valueBuf, len);
            pos += TLV_HDR_SIZE + len;
        }

    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: NV journal loaded (v%d, %d bytes, %d entries)\n",
            (int)hdr.version, (int)ctx->nvWritePos,
            (int)((ctx->nvWritePos - sizeof(FWTPM_NV_HEADER))));
    #endif
        rc = TPM_RC_SUCCESS;
    }
    else {
        /* No valid NV image — generate fresh hierarchy seeds */
        if (rc == TPM_RC_SUCCESS && hdr.magic == FWTPM_NV_MAGIC &&
            hdr.version != FWTPM_NV_VERSION) {
            fprintf(stderr, "WARNING: fwTPM NV version mismatch "
                "(found %d, expected %d) — regenerating seeds\n",
                (int)hdr.version, (int)FWTPM_NV_VERSION);
        }
    #ifdef DEBUG_WOLFTPM
        printf("fwTPM: No NV state found, generating fresh seeds\n");
    #endif

        rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->ownerSeed,
            FWTPM_SEED_SIZE);
        if (rc == 0) {
            rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->endorsementSeed,
                FWTPM_SEED_SIZE);
        }
        if (rc == 0) {
            rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->platformSeed,
                FWTPM_SEED_SIZE);
        }
        if (rc == 0) {
            rc = wc_RNG_GenerateBlock(&ctx->rng, ctx->nullSeed,
                FWTPM_SEED_SIZE);
        }
        if (rc != 0) {
            XFREE(valueBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            return TPM_RC_FAILURE;
        }

        /* Auth values start empty */
        XMEMSET(&ctx->ownerAuth, 0, sizeof(ctx->ownerAuth));
        XMEMSET(&ctx->endorsementAuth, 0, sizeof(ctx->endorsementAuth));
        XMEMSET(&ctx->platformAuth, 0, sizeof(ctx->platformAuth));
        XMEMSET(&ctx->lockoutAuth, 0, sizeof(ctx->lockoutAuth));

    #ifndef FWTPM_NO_DA
        /* DA protection defaults */
        ctx->daMaxTries = 32;
        ctx->daRecoveryTime = 600;
        ctx->daLockoutRecovery = 86400;
        ctx->daFailedTries = 0;
    #endif

        /* PCR auth/policy defaults */
        ctx->pcrAllocatedBanks = FWTPM_PCR_ALLOC_DEFAULT;

        /* Save initial state (compact write) */
        rc = FWTPM_NV_Save(ctx);
    #ifdef DEBUG_WOLFTPM
        if (rc != TPM_RC_SUCCESS) {
            printf("fwTPM: Warning: Failed to save initial NV state (%d)\n",
                rc);
        }
    #endif
    }

    XFREE(valueBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

/* ========================================================================= */
/* Full Save (Compaction)                                                    */
/* ========================================================================= */

/* Write all current state as a clean set of TLV entries (no duplicates).
 * This is used on Shutdown, Clear, and when journal space runs out. */
int FWTPM_NV_Save(FWTPM_CTX* ctx)
{
    FWTPM_NV_HAL* hal;
    int rc = TPM_RC_SUCCESS;
    int i;
    byte* buf = NULL;
    word32 bufSz = FWTPM_NV_MAX_ENTRY;
    word32 pos;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    hal = &ctx->nvHal;
    if (hal->write == NULL) {
        return TPM_RC_FAILURE;
    }

    /* Allocate marshal buffer for largest single entry */
    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    ctx->nvCompacting = 1;

    /* Erase NV storage */
    if (hal->erase != NULL) {
        rc = hal->erase(hal->ctx, 0, hal->maxSize);
    }

    /* Reset write position to after header (only if erase succeeded) */
    if (rc == 0) {
        ctx->nvWritePos = (word32)sizeof(FWTPM_NV_HEADER);
    }

    /* Write header (will be updated at end with final writePos) */
    if (rc == 0) {
        rc = FwNvWriteHeader(ctx);
    }

    /* --- Seeds --- */
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_OWNER_SEED,
            ctx->ownerSeed, FWTPM_SEED_SIZE);
    }
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_ENDORSEMENT_SEED,
            ctx->endorsementSeed, FWTPM_SEED_SIZE);
    }
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PLATFORM_SEED,
            ctx->platformSeed, FWTPM_SEED_SIZE);
    }
    /* Note: null seed is NOT persisted (re-randomized on Startup) */

    /* --- Auth values --- */
    if (rc == 0) {
        pos = 0;
        FwNvMarshalAuth(buf, &pos, bufSz, &ctx->ownerAuth);
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_OWNER_AUTH,
            buf, (UINT16)pos);
    }
    if (rc == 0) {
        pos = 0;
        FwNvMarshalAuth(buf, &pos, bufSz, &ctx->endorsementAuth);
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_ENDORSEMENT_AUTH,
            buf, (UINT16)pos);
    }
    if (rc == 0) {
        pos = 0;
        FwNvMarshalAuth(buf, &pos, bufSz, &ctx->platformAuth);
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PLATFORM_AUTH,
            buf, (UINT16)pos);
    }
    if (rc == 0) {
        pos = 0;
        FwNvMarshalAuth(buf, &pos, bufSz, &ctx->lockoutAuth);
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_LOCKOUT_AUTH,
            buf, (UINT16)pos);
    }

    /* --- PCR state --- */
    if (rc == 0) {
        pos = 0;
        FwNvMarshalBytes(buf, &pos, bufSz,
            (const byte*)ctx->pcrDigest, sizeof(ctx->pcrDigest));
        FwNvMarshalU32(buf, &pos, bufSz, ctx->pcrUpdateCounter);
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PCR_STATE,
            buf, (UINT16)pos);
    }

    /* --- PCR auth/policy (only if any are set) --- */
    if (rc == 0) {
        int hasPcrAuth = 0;
        for (i = 0; i < IMPLEMENTATION_PCR; i++) {
            if (ctx->pcrAuth[i].size > 0 || ctx->pcrPolicy[i].size > 0) {
                hasPcrAuth = 1;
                break;
            }
        }
        if (hasPcrAuth || ctx->pcrAllocatedBanks != FWTPM_PCR_ALLOC_DEFAULT) {
            word32 needed = 1 + IMPLEMENTATION_PCR * (2 + 64 + 2 + 64 + 2);
            if (needed > bufSz) {
                byte* newBuf;
                newBuf = (byte*)XMALLOC(needed, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (newBuf == NULL) {
                    rc = TPM_RC_MEMORY;
                }
                else {
                    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                    buf = newBuf;
                    bufSz = needed;
                }
            }
            if (rc == 0) {
                pos = 0;
                FwNvMarshalU8(buf, &pos, bufSz, ctx->pcrAllocatedBanks);
                for (i = 0; i < IMPLEMENTATION_PCR; i++) {
                    FwNvMarshalAuth(buf, &pos, bufSz, &ctx->pcrAuth[i]);
                    FwNvMarshalDigest(buf, &pos, bufSz,
                        &ctx->pcrPolicy[i]);
                    FwNvMarshalU16(buf, &pos, bufSz,
                        ctx->pcrPolicyAlg[i]);
                }
                rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PCR_AUTH,
                    buf, (UINT16)pos);
            }
        }
    }

    /* --- Flags --- */
    if (rc == 0) {
        pos = 0;
        FwNvMarshalU8(buf, &pos, bufSz,
            (UINT8)(ctx->disableClear ? 0x01 : 0x00));
    #ifndef FWTPM_NO_DA
        FwNvMarshalU32(buf, &pos, bufSz, ctx->daMaxTries);
        FwNvMarshalU32(buf, &pos, bufSz, ctx->daRecoveryTime);
        FwNvMarshalU32(buf, &pos, bufSz, ctx->daLockoutRecovery);
    #endif
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_FLAGS, buf, (UINT16)pos);
    }

    /* --- Clock offset --- */
    if (rc == 0 && ctx->clockOffset != 0) {
        pos = 0;
        FwNvMarshalU32(buf, &pos, bufSz,
            (UINT32)(ctx->clockOffset & 0xFFFFFFFF));
        FwNvMarshalU32(buf, &pos, bufSz,
            (UINT32)(ctx->clockOffset >> 32));
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_CLOCK, buf, (UINT16)pos);
    }

    /* --- Hierarchy policies --- */
    for (i = 0; i < 4 && rc == 0; i++) {
        UINT32 hier;
        TPM2B_DIGEST* policy;
        TPMI_ALG_HASH alg;

        switch (i) {
            case 0:
                hier = TPM_RH_OWNER;
                policy = &ctx->ownerPolicy;
                alg = ctx->ownerPolicyAlg;
                break;
            case 1:
                hier = TPM_RH_ENDORSEMENT;
                policy = &ctx->endorsementPolicy;
                alg = ctx->endorsementPolicyAlg;
                break;
            case 2:
                hier = TPM_RH_PLATFORM;
                policy = &ctx->platformPolicy;
                alg = ctx->platformPolicyAlg;
                break;
            default:
                hier = TPM_RH_LOCKOUT;
                policy = &ctx->lockoutPolicy;
                alg = ctx->lockoutPolicyAlg;
                break;
        }

        if (policy->size > 0) {
            pos = 0;
            FwNvMarshalU32(buf, &pos, bufSz, hier);
            FwNvMarshalU16(buf, &pos, bufSz, alg);
            FwNvMarshalDigest(buf, &pos, bufSz, policy);
            rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_HIERARCHY_POLICY,
                buf, (UINT16)pos);
        }
    }

    /* --- NV indices (only used slots) --- */
    for (i = 0; i < FWTPM_MAX_NV_INDICES && rc == 0; i++) {
        if (ctx->nvIndices[i].inUse) {
            word32 needed;
            pos = 0;
            /* Estimate: ensure buf is large enough */
            needed = 4 + 2 + 4 + FWTPM_NV_NAME_EST + 2 + /* nvPublic */
                     FWTPM_NV_AUTH_EST + /* auth */
                     1 + 2 + ctx->nvIndices[i].nvPublic.dataSize;
            if (needed > bufSz) {
                byte* newBuf;
                newBuf = (byte*)XMALLOC(needed, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (newBuf == NULL) {
                    rc = TPM_RC_MEMORY;
                    break;
                }
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                buf = newBuf;
                bufSz = needed;
            }
            rc = FwNvMarshalNvIndex(buf, &pos, bufSz, &ctx->nvIndices[i]);
            if (rc == 0) {
                rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_NV_INDEX,
                    buf, (UINT16)pos);
            }
        }
    }

    /* --- Persistent objects (only used slots) --- */
    for (i = 0; i < FWTPM_MAX_PERSISTENT && rc == 0; i++) {
        if (ctx->persistent[i].used) {
            word32 needed;
            pos = 0;
            needed = 4 + FWTPM_NV_PUBAREA_EST + FWTPM_NV_NAME_EST + 2 +
                     ctx->persistent[i].privKeySize + FWTPM_NV_AUTH_EST;
            if (needed > bufSz) {
                byte* newBuf;
                newBuf = (byte*)XMALLOC(needed, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (newBuf == NULL) {
                    rc = TPM_RC_MEMORY;
                    break;
                }
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                buf = newBuf;
                bufSz = needed;
            }
            rc = FwNvMarshalObject(buf, &pos, bufSz, &ctx->persistent[i]);
            if (rc == 0) {
                rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PERSISTENT,
                    buf, (UINT16)pos);
            }
        }
    }

    /* --- Primary cache (only used slots) --- */
    for (i = 0; i < FWTPM_MAX_PRIMARY_CACHE && rc == 0; i++) {
        if (ctx->primaryCache[i].used) {
            word32 needed;
            pos = 0;
            needed = 4 + 32 + FWTPM_NV_PUBAREA_EST + 2 +
                     ctx->primaryCache[i].privKeySize;
            if (needed > bufSz) {
                byte* newBuf;
                newBuf = (byte*)XMALLOC(needed, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER);
                if (newBuf == NULL) {
                    rc = TPM_RC_MEMORY;
                    break;
                }
                XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                buf = newBuf;
                bufSz = needed;
            }
            rc = FwNvMarshalPrimaryCache(buf, &pos, bufSz,
                &ctx->primaryCache[i]);
            if (rc == 0) {
                rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PRIMARY_CACHE,
                    buf, (UINT16)pos);
            }
        }
    }

    /* Update header with final writePos */
    if (rc == 0) {
        rc = FwNvWriteHeader(ctx);
    }

#ifdef DEBUG_WOLFTPM
    printf("fwTPM: NV saved (compact, %d bytes)\n", (int)ctx->nvWritePos);
#endif

    ctx->nvCompacting = 0;
    TPM2_ForceZero(buf, bufSz);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

/* ========================================================================= */
/* Targeted Save Functions                                                   */
/* ========================================================================= */

int FWTPM_NV_SaveSeeds(FWTPM_CTX* ctx)
{
    int rc;
    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }
    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_OWNER_SEED,
        ctx->ownerSeed, FWTPM_SEED_SIZE);
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_ENDORSEMENT_SEED,
            ctx->endorsementSeed, FWTPM_SEED_SIZE);
    }
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PLATFORM_SEED,
            ctx->platformSeed, FWTPM_SEED_SIZE);
    }
    return rc;
}

int FWTPM_NV_SaveAuth(FWTPM_CTX* ctx, UINT32 hierarchy)
{
    int rc;
    byte buf[2 + TPM_SHA384_DIGEST_SIZE];
    word32 pos = 0;
    UINT16 tag;
    TPM2B_AUTH* auth;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (hierarchy) {
        case TPM_RH_OWNER:
            tag = FWTPM_NV_TAG_OWNER_AUTH;
            auth = &ctx->ownerAuth;
            break;
        case TPM_RH_ENDORSEMENT:
            tag = FWTPM_NV_TAG_ENDORSEMENT_AUTH;
            auth = &ctx->endorsementAuth;
            break;
        case TPM_RH_PLATFORM:
            tag = FWTPM_NV_TAG_PLATFORM_AUTH;
            auth = &ctx->platformAuth;
            break;
        case TPM_RH_LOCKOUT:
            tag = FWTPM_NV_TAG_LOCKOUT_AUTH;
            auth = &ctx->lockoutAuth;
            break;
        default:
            return TPM_RC_HIERARCHY;
    }

    rc = FwNvMarshalAuth(buf, &pos, sizeof(buf), auth);
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, tag, buf, (UINT16)pos);
    }
    return rc;
}

int FWTPM_NV_SavePcrState(FWTPM_CTX* ctx)
{
    int rc;
    byte* buf;
    word32 pos = 0;
    word32 bufSz = (word32)sizeof(ctx->pcrDigest) + 4;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    FwNvMarshalBytes(buf, &pos, bufSz,
        (const byte*)ctx->pcrDigest, sizeof(ctx->pcrDigest));
    FwNvMarshalU32(buf, &pos, bufSz, ctx->pcrUpdateCounter);

    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PCR_STATE, buf, (UINT16)pos);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

int FWTPM_NV_SavePcrAuth(FWTPM_CTX* ctx)
{
    int rc;
    int i;
    byte* buf;
    word32 pos = 0;
    word32 bufSz = 1 + IMPLEMENTATION_PCR * (2 + 64 + 2 + 64 + 2);

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    FwNvMarshalU8(buf, &pos, bufSz, ctx->pcrAllocatedBanks);
    for (i = 0; i < IMPLEMENTATION_PCR; i++) {
        FwNvMarshalAuth(buf, &pos, bufSz, &ctx->pcrAuth[i]);
        FwNvMarshalDigest(buf, &pos, bufSz, &ctx->pcrPolicy[i]);
        FwNvMarshalU16(buf, &pos, bufSz, ctx->pcrPolicyAlg[i]);
    }

    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PCR_AUTH, buf, (UINT16)pos);

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

int FWTPM_NV_SaveFlags(FWTPM_CTX* ctx)
{
    int rc;
    byte buf[1 + 12]; /* flags + DA params */
    word32 pos = 0;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    FwNvMarshalU8(buf, &pos, sizeof(buf),
        (UINT8)(ctx->disableClear ? 0x01 : 0x00));
#ifndef FWTPM_NO_DA
    FwNvMarshalU32(buf, &pos, sizeof(buf), ctx->daMaxTries);
    FwNvMarshalU32(buf, &pos, sizeof(buf), ctx->daRecoveryTime);
    FwNvMarshalU32(buf, &pos, sizeof(buf), ctx->daLockoutRecovery);
#endif

    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_FLAGS, buf, (UINT16)pos);
    return rc;
}

int FWTPM_NV_SaveClock(FWTPM_CTX* ctx)
{
    int rc;
    byte buf[8]; /* UINT64 as two U32 (lo, hi) */
    word32 pos = 0;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    FwNvMarshalU32(buf, &pos, sizeof(buf),
        (UINT32)(ctx->clockOffset & 0xFFFFFFFF));
    FwNvMarshalU32(buf, &pos, sizeof(buf),
        (UINT32)(ctx->clockOffset >> 32));

    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_CLOCK, buf, (UINT16)pos);
    return rc;
}

int FWTPM_NV_SaveHierarchyPolicy(FWTPM_CTX* ctx, UINT32 hierarchy)
{
    int rc;
    byte buf[4 + 2 + 2 + 64]; /* hierarchy + alg + digest */
    word32 pos = 0;
    TPM2B_DIGEST* policy;
    TPMI_ALG_HASH alg;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    switch (hierarchy) {
        case TPM_RH_OWNER:
            policy = &ctx->ownerPolicy;
            alg = ctx->ownerPolicyAlg;
            break;
        case TPM_RH_ENDORSEMENT:
            policy = &ctx->endorsementPolicy;
            alg = ctx->endorsementPolicyAlg;
            break;
        case TPM_RH_PLATFORM:
            policy = &ctx->platformPolicy;
            alg = ctx->platformPolicyAlg;
            break;
        case TPM_RH_LOCKOUT:
            policy = &ctx->lockoutPolicy;
            alg = ctx->lockoutPolicyAlg;
            break;
        default:
            return TPM_RC_HIERARCHY;
    }

    FwNvMarshalU32(buf, &pos, sizeof(buf), hierarchy);
    FwNvMarshalU16(buf, &pos, sizeof(buf), alg);
    FwNvMarshalDigest(buf, &pos, sizeof(buf), policy);

    rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_HIERARCHY_POLICY,
        buf, (UINT16)pos);
    return rc;
}

int FWTPM_NV_SaveNvIndex(FWTPM_CTX* ctx, int slot)
{
    int rc;
    byte* buf;
    word32 pos = 0;
    word32 bufSz;
    const FWTPM_NvIndex* nv;

    if (ctx == NULL || slot < 0 || slot >= FWTPM_MAX_NV_INDICES) {
        return BAD_FUNC_ARG;
    }

    nv = &ctx->nvIndices[slot];
    if (!nv->inUse) {
        return BAD_FUNC_ARG;
    }

    /* Estimate buffer size */
    bufSz = 4 + 2 + 4 + 2 + FWTPM_NV_NAME_EST + 2 + /* nvPublic */
            FWTPM_NV_AUTH_EST + /* auth */
            1 + 2 + nv->nvPublic.dataSize; /* written + data */

    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    rc = FwNvMarshalNvIndex(buf, &pos, bufSz, nv);
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_NV_INDEX,
            buf, (UINT16)pos);
    }

    TPM2_ForceZero(buf, bufSz);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

int FWTPM_NV_DeleteNvIndex(FWTPM_CTX* ctx, UINT32 nvHandle)
{
    byte buf[4];
    word32 pos = 0;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    FwNvMarshalU32(buf, &pos, sizeof(buf), nvHandle);
    return FwNvAppendEntry(ctx, FWTPM_NV_TAG_NV_INDEX_DEL,
        buf, (UINT16)pos);
}

int FWTPM_NV_SavePersistent(FWTPM_CTX* ctx, int slot)
{
    int rc;
    byte* buf;
    word32 pos = 0;
    word32 bufSz;
    const FWTPM_Object* obj;

    if (ctx == NULL || slot < 0 || slot >= FWTPM_MAX_PERSISTENT) {
        return BAD_FUNC_ARG;
    }

    obj = &ctx->persistent[slot];
    if (!obj->used) {
        return BAD_FUNC_ARG;
    }

    bufSz = 4 + FWTPM_NV_PUBAREA_EST + 2 + FWTPM_NV_NAME_EST + 2 +
            obj->privKeySize + 2 + FWTPM_NV_AUTH_EST;

    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    rc = FwNvMarshalObject(buf, &pos, bufSz, obj);
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PERSISTENT,
            buf, (UINT16)pos);
    }

    TPM2_ForceZero(buf, bufSz);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

int FWTPM_NV_DeletePersistent(FWTPM_CTX* ctx, UINT32 handle)
{
    byte buf[4];
    word32 pos = 0;

    if (ctx == NULL) {
        return BAD_FUNC_ARG;
    }

    FwNvMarshalU32(buf, &pos, sizeof(buf), handle);
    return FwNvAppendEntry(ctx, FWTPM_NV_TAG_PERSISTENT_DEL,
        buf, (UINT16)pos);
}

int FWTPM_NV_SavePrimaryCache(FWTPM_CTX* ctx, int slot)
{
    int rc;
    byte* buf;
    word32 pos = 0;
    word32 bufSz;
    const FWTPM_PrimaryCache* cache;

    if (ctx == NULL || slot < 0 || slot >= FWTPM_MAX_PRIMARY_CACHE) {
        return BAD_FUNC_ARG;
    }

    cache = &ctx->primaryCache[slot];
    if (!cache->used) {
        return BAD_FUNC_ARG;
    }

    bufSz = 4 + 32 + FWTPM_NV_PUBAREA_EST + 2 + cache->privKeySize;

    buf = (byte*)XMALLOC(bufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        return TPM_RC_MEMORY;
    }

    rc = FwNvMarshalPrimaryCache(buf, &pos, bufSz, cache);
    if (rc == 0) {
        rc = FwNvAppendEntry(ctx, FWTPM_NV_TAG_PRIMARY_CACHE,
            buf, (UINT16)pos);
    }

    TPM2_ForceZero(buf, bufSz);
    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return rc;
}

#endif /* WOLFTPM_FWTPM */
