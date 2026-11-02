/* swtpm_uart_unit_tests.c
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

/* Tests for the SWTPM UART receive path. A pseudo-terminal stands in for the
 * serial device and a forked child plays the TPM, so neither hardware nor a
 * simulator is required. tpm2_swtpm.c is compiled into this binary because
 * TPM2_SWTPM_SendCommand is WOLFTPM_LOCAL.
 *
 * tests/include.am shortens the receive deadline and the per-read VTIME, so
 * the timeout case does not take the production 60 seconds. */

/* posix_openpt, grantpt, unlockpt and ptsname. Other platforms declare them
 * without a feature macro, and on macOS _XOPEN_SOURCE hides usleep. */
#if defined(__linux__)
    #ifndef _XOPEN_SOURCE
        #define _XOPEN_SOURCE 600
    #endif
    #ifndef _DEFAULT_SOURCE
        #define _DEFAULT_SOURCE
    #endif
#endif

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_swtpm.h>
#include <wolftpm/tpm2_packet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(WOLFTPM_SWTPM) && defined(WOLFTPM_SWTPM_UART) && \
    !defined(_WIN32) && defined(CLOCK_MONOTONIC)

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/resource.h>

/* Kept in step with the defaults in src/tpm2_swtpm.c, for a build that does
 * not override them. tests/include.am shortens both. */
#ifndef WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS
    #define WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS 60
#endif
#ifndef WOLFTPM_SWTPM_UART_VTIME
    #define WOLFTPM_SWTPM_UART_VTIME 200
#endif

/* How the child behaves once it has read the command */
#define TEST_RSP_DELAYED  1 /* answer after several VTIME periods */
#define TEST_RSP_SILENT   2 /* hold the line open and say nothing */
#define TEST_RSP_HANGUP   3 /* drop the peer */

/* mssim framing: TPM_SEND_COMMAND, locality, command size */
#define TEST_CMD_HDR_SZ   9
#define TEST_CMD_SZ       12
#define TEST_RSP_SZ       10
/* response size, response, ack */
#define TEST_RSP_WIRE_SZ  (4 + TEST_RSP_SZ + 4)
/* Well inside the deadline, and many VTIME periods at the test's VTIME */
#define TEST_DELAY_MS     1500
/* A receive that waits on poll() costs no measurable CPU. Retrying a read
 * instead burns a whole core, so this is what catches a busy loop. */
#define TEST_MAX_CPU_SECS 0.5

static int gFailures = 0;

static double TestNowSec(void)
{
    struct timespec ts;
    double now = 0;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        now = (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
    }
    return now;
}

/* CPU seconds consumed by this process so far */
static double TestCpuSec(void)
{
    struct rusage ru;
    double cpu = 0;

    if (getrusage(RUSAGE_SELF, &ru) == 0) {
        cpu = (double)ru.ru_utime.tv_sec +
              ((double)ru.ru_utime.tv_usec / 1000000.0) +
              (double)ru.ru_stime.tv_sec +
              ((double)ru.ru_stime.tv_usec / 1000000.0);
    }
    return cpu;
}

/* Read exactly len bytes. Returns 0 on success. */
static int TestReadFull(int fd, byte* buf, size_t len)
{
    ssize_t got;
    int rc = 0;

    while (len > 0) {
        got = read(fd, buf, len);
        if (got <= 0) {
            rc = -1;
            break;
        }
        buf += got;
        len -= (size_t)got;
    }
    return rc;
}

/* Runs in the forked child, which is the only holder of the master side. */
static void TestServeTpm(int master, int behavior)
{
    byte hdr[TEST_CMD_HDR_SZ];
    byte cmd[TEST_CMD_SZ];
    byte rsp[TEST_RSP_WIRE_SZ];
    UINT32 cmdSz;

    if (TestReadFull(master, hdr, sizeof(hdr)) != 0) {
        _exit(1);
    }
    cmdSz = ((UINT32)hdr[5] << 24) | ((UINT32)hdr[6] << 16) |
            ((UINT32)hdr[7] << 8)  |  (UINT32)hdr[8];
    if (cmdSz != TEST_CMD_SZ || TestReadFull(master, cmd, cmdSz) != 0) {
        _exit(1);
    }

    if (behavior == TEST_RSP_HANGUP) {
        close(master);
        _exit(0);
    }
    if (behavior == TEST_RSP_SILENT) {
        /* Outlast the deadline without closing, so the client has to time
         * out rather than see a hangup. */
        sleep(WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS + 2);
        _exit(0);
    }

    /* TEST_RSP_DELAYED: answer after far more than one VTIME period */
    usleep(TEST_DELAY_MS * 1000);
    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[3] = TEST_RSP_SZ;           /* response size */
    rsp[4] = 0x80; rsp[5] = 0x01;   /* TPM_ST_NO_SESSIONS */
    rsp[9] = TEST_RSP_SZ;           /* size inside the response header */
    /* the remaining bytes are TPM_RC_SUCCESS and a zero ack */
    if (write(master, rsp, sizeof(rsp)) != (ssize_t)sizeof(rsp)) {
        _exit(1);
    }
    /* Stay open for the TPM_SESSION_END that follows the response */
    (void)TestReadFull(master, hdr, 4);
    _exit(0);
}

/* Drive one command over a pty and report what the client did. Returns the
 * result code, with the wall-clock time in elapsed and the CPU time the call
 * cost in cpu. */
static int TestSendOverPty(int behavior, double* elapsed, double* cpu)
{
    TPM2_CTX ctx;
    TPM2_Packet packet;
    byte buf[256];
    char devPath[64];
    const char* ptsPath;
    double start;
    double cpuStart;
    pid_t pid;
    int master;
    int status = 0;
    int rc;

    *elapsed = 0;
    *cpu = 0;

    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0 || grantpt(master) != 0 || unlockpt(master) != 0) {
        printf("pty setup failed\n");
        return TPM_RC_FAILURE;
    }
    ptsPath = ptsname(master);
    if (ptsPath == NULL) {
        printf("ptsname failed\n");
        close(master);
        return TPM_RC_FAILURE;
    }
    strncpy(devPath, ptsPath, sizeof(devPath) - 1);
    devPath[sizeof(devPath) - 1] = '\0';

    pid = fork();
    if (pid < 0) {
        printf("fork failed\n");
        close(master);
        return TPM_RC_FAILURE;
    }
    if (pid == 0) {
        TestServeTpm(master, behavior);
        _exit(1);
    }

    /* The child now owns the master side, so closing it here means a child
     * exit really does hang the line up. */
    close(master);
    setenv("TPM2_SWTPM_HOST", devPath, 1);

    XMEMSET(&ctx, 0, sizeof(ctx));
    ctx.tcpCtx.fd = -1;
    XMEMSET(&packet, 0, sizeof(packet));
    XMEMSET(buf, 0, sizeof(buf));
    buf[0] = 0x80; buf[1] = 0x01;   /* TPM_ST_NO_SESSIONS */
    buf[5] = TEST_CMD_SZ;
    packet.buf = buf;
    packet.size = (int)sizeof(buf);
    packet.pos = TEST_CMD_SZ;

    start = TestNowSec();
    cpuStart = TestCpuSec();
    rc = TPM2_SWTPM_SendCommand(&ctx, &packet);
    *elapsed = TestNowSec() - start;
    *cpu = TestCpuSec() - cpuStart;

    TPM2_SwtpmClose(&ctx);
    /* The silent child is still sleeping out its timer */
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);

    return rc;
}

static void TestCheck(const char* name, int pass, double elapsed, double cpu)
{
    printf("Test SWTPM UART:  %-40s %s (%.2fs wall, %.2fs cpu)\n", name,
        pass ? "Passed" : "FAILED", elapsed, cpu);
    if (!pass) {
        gFailures++;
    }
}

/* A response arriving many VTIME periods late must still be accepted. Before
 * the poll based deadline, the first zero byte read was treated as EOF and
 * any command slower than one period failed. */
static void test_SwTpmUart_LateResponse(void)
{
    double elapsed = 0;
    double cpu = 0;
    int rc = TestSendOverPty(TEST_RSP_DELAYED, &elapsed, &cpu);

    TestCheck("late response accepted",
        rc == TPM_RC_SUCCESS &&
        elapsed >= (((double)TEST_DELAY_MS / 1000.0) - 0.1) &&
        elapsed < (double)WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS &&
        cpu < TEST_MAX_CPU_SECS,
        elapsed, cpu);
}

/* Silence must fail at the cumulative deadline, not at some multiple of it. */
static void test_SwTpmUart_Timeout(void)
{
    double elapsed = 0;
    double cpu = 0;
    int rc = TestSendOverPty(TEST_RSP_SILENT, &elapsed, &cpu);

    TestCheck("silence times out at the deadline",
        rc != TPM_RC_SUCCESS &&
        elapsed >= ((double)WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS - 0.5) &&
        elapsed <= ((double)WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS + 1.0) &&
        cpu < TEST_MAX_CPU_SECS,
        elapsed, cpu);
}

/* A hung up line returns a zero byte read with no delay. Retrying that read
 * spins on the CPU until the deadline, so it has to fail promptly instead. */
static void test_SwTpmUart_Hangup(void)
{
    double elapsed = 0;
    double cpu = 0;
    int rc = TestSendOverPty(TEST_RSP_HANGUP, &elapsed, &cpu);

    TestCheck("hangup fails promptly",
        rc != TPM_RC_SUCCESS &&
        elapsed < ((double)WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS / 2.0) &&
        cpu < TEST_MAX_CPU_SECS,
        elapsed, cpu);
}

int main(void)
{
    printf("SWTPM UART tests, deadline %d secs, VTIME %d\n",
        WOLFTPM_SWTPM_UART_RX_TIMEOUT_SECS, WOLFTPM_SWTPM_UART_VTIME);

    test_SwTpmUart_LateResponse();
    test_SwTpmUart_Timeout();
    test_SwTpmUart_Hangup();

    if (gFailures != 0) {
        printf("SWTPM UART tests: %d failed\n", gFailures);
        return 1;
    }
    printf("SWTPM UART tests: all passed\n");
    return 0;
}

#else /* !WOLFTPM_SWTPM_UART */

int main(void)
{
    printf("SWTPM UART tests skipped\n");
    return 0;
}

#endif
