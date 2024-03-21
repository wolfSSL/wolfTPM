/* ifx_fw_extract.c
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

/* Tool source based on simple-update example from
 * Infineon Technologies AG (www.infineon.com).
 * This is a stand-alone host side tool for extracting the firmware
 * manifest and data files from a supplied .bin
 */


#define _DEFAULT_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Endianess helpers */
#if defined(__MACH__) || defined(__APPLE__)
    #include <machine/endian.h>
    #include <libkern/OSByteOrder.h>

    #define htobe16(x) OSSwapHostToBigInt16(x)
    #define htole16(x) OSSwapHostToLittleInt16(x)
    #define be16toh(x) OSSwapBigToHostInt16(x)
    #define le16toh(x) OSSwapLittleToHostInt16(x)

    #define htobe32(x) OSSwapHostToBigInt32(x)
    #define htole32(x) OSSwapHostToLittleInt32(x)
    #define be32toh(x) OSSwapBigToHostInt32(x)
    #define le32toh(x) OSSwapLittleToHostInt32(x)

    #define htobe64(x) OSSwapHostToBigInt64(x)
    #define htole64(x) OSSwapHostToLittleInt64(x)
    #define be64toh(x) OSSwapBigToHostInt64(x)
    #define le64toh(x) OSSwapLittleToHostInt64(x)
#else
    #include <endian.h>
#endif

/* Helper to print file and line */
#define LOG(t) { printf(__FILE__":%i: %s\n", __LINE__, t); }

#define READ_BE16(dest, buf, size, off) { \
    if (off + sizeof(dest) >= size) { \
        LOG("FW file too short"); \
        return -1; \
    } \
    memcpy(&dest, &fw[off], sizeof(dest)); \
    dest = be16toh(dest); \
    off += sizeof(dest); \
}

#define READ_BE32(dest, buf, size, off) { \
    if (off + sizeof(dest) >= size) { \
        LOG("FW file too short"); \
        return -1; \
    } \
    memcpy(&dest, &fw[off], sizeof(dest)); \
    dest = be32toh(dest); \
    off += sizeof(dest); \
}

static int extractFW(
    uint8_t *fw, size_t fw_size, uint32_t keygroup_id,
    uint8_t **manifest, size_t *manifest_size,
    uint8_t **data, size_t *data_size)
{
    size_t offset = 0, offset2;
    uint16_t size16, num;
    uint32_t size32, group;

    const uint8_t guid[] = { 0x1a, 0x53, 0x66, 0x7a,
                             0xfb, 0x12, 0x47, 0x9e,
                             0xac, 0x58, 0xec, 0x99,
                             0x58, 0x86, 0x10, 0x94 };

    if (offset + sizeof(guid) > fw_size) {
        LOG("FW file too short");
        return -1;
    }
    if (memcmp(&fw[offset], &guid[0], sizeof(guid)) != 0) {
        LOG("Wrong GUID");
        return -1;
    }
    offset += sizeof(guid) + 1;

    READ_BE16(size16, fw, fw_size, offset);
    offset += size16 + 1;

    READ_BE16(size16, fw, fw_size, offset);
    offset += size16;

    READ_BE16(size16, fw, fw_size, offset);
    offset2 = offset;
    offset += size16;

    READ_BE16(size16, fw, offset, offset2);
    offset2 += size16;

    READ_BE16(num, fw, offset, offset2);

    *manifest = NULL;
    for (int i = 0; i < num; i++) {
        READ_BE32(group, fw, offset, offset2);
        printf("Found group %08x\n", group);

        READ_BE16(size16, fw, offset, offset2);

        if (group == keygroup_id) {
            printf("Chosen group found: %08x\n", group);
            *manifest = &fw[offset2];
            *manifest_size = size16;
        }
        offset2 += size16;
    }
    if (*manifest == NULL) {
        if (keygroup_id == 0) {
            /* just list key groups */
            return 0;
        }
        LOG("Chosen group not found");
        return -1;
    }

    printf("Manifest size is %zi\n", *manifest_size);
    if (offset2 != offset) {
        LOG("Bad Manifest size");
        return -1;
    }

    READ_BE32(size32, fw, fw_size, offset);
    if (offset + size32 >= fw_size) {
        LOG("FW file too short");
        return -1;
    }
    *data = &fw[offset];
    *data_size = size32;
    offset += size32;
    printf("Data size is %zi\n", *data_size);

    READ_BE16(size16, fw, fw_size, offset);
    offset += size16 + 4;

    if (offset != fw_size) {
        LOG("Wrong FW file size");
        printf("offset at %zi, fw_size at %zi\n", offset, fw_size);
        return -1;
    }

    return 0;
}

static int readfile(const char *filename, uint8_t **buffer, size_t *size)
{
    int rc;
    int fd;
    struct stat sb;

    printf("Reading %s\n", filename);

    fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open");
        return fd;
    }
    rc = fstat(fd, &sb);
    if (rc == -1) {
        perror("fstat");
        goto close;
    }

    uint8_t *addr = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        goto close;
    }

    *buffer = malloc(sb.st_size);
    if (!buffer) {
        perror("malloc");
        goto unmap;
    }
    memcpy(*buffer, addr, sb.st_size);
    *size = sb.st_size;

unmap:
    munmap(addr, sb.st_size);

close:
    close(fd);

    return 0;
}

static int writefile(const char *filename, uint8_t *buffer, size_t size)
{
    int fd;
    ssize_t ret;

    printf("Writing %s\n", filename);

    fd = open(filename, (O_WRONLY | O_CREAT | O_EXCL), 0644);
    if (fd == -1) {
        perror("open");
        return fd;
    }

    ret = write(fd, buffer, size);
    if (ret < 0 || ((size_t) ret) != size) {
        perror("write");
        goto close;
    }

close:
    close(fd);

    return 0;
}

int main(int argc, char **argv)
{
    int rc;
    uint8_t *manifest = NULL, *data = NULL, *fw;
    size_t manifest_size, data_size, fw_size;
    uint32_t keygroup_id = 0;

    if (argc <= 1 ||
        strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[argc-1], "-h") == 0 || strcmp(argv[argc-1], "--help") == 0)
    {
        printf("Usage:\n");
        printf("  ifx_fw_extract <fw-file>\n");
        printf("  ifx_fw_extract <fw-file> <keygroup_id> <manifest-file> <data-file>\n");
        exit(1);
    }

    if (argc >= 2) {
        if (readfile(argv[1], &fw, &fw_size) < 0) {
            LOG("Cannot read FW file.");
            return 1;
        }

        if (argc >= 3) {
            if (sscanf(argv[2], "0x%08x", &keygroup_id) != 1 && sscanf(argv[2], "%08x", &keygroup_id) != 1) {
                LOG("Cannot read keygroup_id.");
                return 1;
            }
        }
        rc = extractFW(fw, fw_size, keygroup_id,
                       &manifest, &manifest_size,
                       &data, &data_size);
        if (rc != 0) {
            printf(__FILE__":%i: Received error 0x%08x\n", __LINE__, rc);
            goto errorout;
        }

        if (argc >= 5) {
            if (writefile(argv[3], manifest, manifest_size) < 0)
                return 1;
            if (writefile(argv[4], data, data_size) < 0)
                return 1;
        }
        return 0;
    }
    else {
        printf("Bad arguments.\n");
        goto errorout;
    }

errorout:
    return EXIT_FAILURE;
}
