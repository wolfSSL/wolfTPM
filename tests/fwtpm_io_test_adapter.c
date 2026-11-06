/* Compile the socket transport for focused unit testing without pulling the
 * optional SPDM responder into the core fwTPM unit-test target. */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/fwtpm/fwtpm.h>
#include <wolftpm/fwtpm/fwtpm_io.h>

#ifdef HAVE_CONFIG_H
    #undef HAVE_CONFIG_H
#endif
#ifdef WOLFTPM_SPDM_RESPONDER
    #undef WOLFTPM_SPDM_RESPONDER
#endif

#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

/* Force short vectored writes: each call transfers at most gWritevLimit bytes
 * (0 means no limit), which a real socket does only under memory pressure. */
#if !defined(_WIN32) && !defined(WOLFTPM_ZEPHYR) && !defined(FWTPM_NO_WRITEV)
#define FWTPM_TEST_WRITEV
#include <sys/uio.h>

static size_t gWritevLimit;
static int gWritevCalls;

static ssize_t TestWritev(int fd, const struct iovec* iov, int cnt)
{
    struct iovec capped[3];
    size_t left = gWritevLimit;
    int n = 0;

    gWritevCalls++;
    if (gWritevLimit == 0) {
        return writev(fd, iov, cnt);
    }
    while (n < cnt && n < 3 && left > 0) {
        capped[n].iov_base = iov[n].iov_base;
        capped[n].iov_len = (iov[n].iov_len < left) ? iov[n].iov_len : left;
        left -= capped[n].iov_len;
        n++;
    }
    return writev(fd, capped, n);
}
#define writev TestWritev
#endif

/* Inspect the sockets ServerLoop watches just before it blocks, while they are
 * still open: anything that is not a listener is an accepted client. */
#ifndef _WIN32
#define FWTPM_TEST_SELECT_POLLS 8

static FWTPM_CTX* gSelectCtx;
static int gSelectPolls;
static int gCmdNoDelay;
static int gPlatNoDelay;

static int TestSocketPort(int fd)
{
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

    if (getsockname(fd, (struct sockaddr*)&addr, &len) != 0) {
        return -1;
    }
    return (int)ntohs(addr.sin_port);
}

static int TestSelect(int nfds, fd_set* readFds, fd_set* writeFds,
    fd_set* errFds, struct timeval* tv)
{
    int fd;

    if (gSelectCtx == NULL) {
        return select(nfds, readFds, writeFds, errFds, tv);
    }

    for (fd = 0; fd < nfds; fd++) {
        int noDelay = 0;
        socklen_t len = sizeof(noDelay);

        if (!FD_ISSET(fd, readFds) || fd == gSelectCtx->io.listenFd ||
                fd == gSelectCtx->io.platListenFd) {
            continue;
        }
        if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &noDelay, &len) != 0) {
            continue;
        }
        if (TestSocketPort(fd) == gSelectCtx->cmdPort) {
            gCmdNoDelay = noDelay;
        }
        else if (TestSocketPort(fd) == gSelectCtx->platPort) {
            gPlatNoDelay = noDelay;
        }
    }

    /* A short poll limit fails the test rather than hanging it if a client
     * is never accepted. */
    if (++gSelectPolls >= FWTPM_TEST_SELECT_POLLS ||
            (gCmdNoDelay >= 0 && gPlatNoDelay >= 0)) {
        FWTPM_IO_RequestStop();
        return 0;
    }
    /* Let the accept for the other port be picked up without a full poll */
    tv->tv_sec = 0;
    tv->tv_usec = 10000;
    return select(nfds, readFds, writeFds, errFds, tv);
}
#define select TestSelect
#endif

#include "../src/fwtpm/fwtpm_io.c"

int FWTPM_IO_TestHandleMssimSignal(FWTPM_CTX* ctx, SOCKET_T clientFd,
    UINT32 tssCmd);

int FWTPM_IO_TestHandleMssimSignal(FWTPM_CTX* ctx, SOCKET_T clientFd,
    UINT32 tssCmd)
{
    return HandleMssimSignal(ctx, clientFd, tssCmd);
}

int FWTPM_IO_TestSendMssimReply(FWTPM_CTX* ctx, SOCKET_T clientFd,
    const byte* rsp, int rspSize);

int FWTPM_IO_TestSendMssimReply(FWTPM_CTX* ctx, SOCKET_T clientFd,
    const byte* rsp, int rspSize)
{
    return SendMssimReply(ctx, clientFd, rsp, rspSize);
}

/* Limit each writev to limit bytes and reset the call count. Returns 0, or -1
 * when this build sends replies without writev. */
int FWTPM_IO_TestSetWritevLimit(size_t limit);

int FWTPM_IO_TestSetWritevLimit(size_t limit)
{
#ifdef FWTPM_TEST_WRITEV
    gWritevLimit = limit;
    gWritevCalls = 0;
    return 0;
#else
    (void)limit;
    return -1;
#endif
}

int FWTPM_IO_TestWritevCalls(void);

int FWTPM_IO_TestWritevCalls(void)
{
#ifdef FWTPM_TEST_WRITEV
    return gWritevCalls;
#else
    return 0;
#endif
}

#ifndef _WIN32
static int TestConnectLoopback(int port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    XMEMSET(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

/* Run ServerLoop on ephemeral ports with a client connected to each, and report
 * TCP_NODELAY on the sockets it accepted (-1 if a socket was never accepted). */
int FWTPM_IO_TestAcceptNoDelay(FWTPM_CTX* ctx, int* cmdNoDelay,
    int* platNoDelay);

int FWTPM_IO_TestAcceptNoDelay(FWTPM_CTX* ctx, int* cmdNoDelay,
    int* platNoDelay)
{
    int rc;
    int cmdClient = -1;
    int platClient = -1;

    ctx->cmdPort = 0;
    ctx->platPort = 0;
    rc = FWTPM_IO_Init(ctx);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    ctx->cmdPort = TestSocketPort(ctx->io.listenFd);
    ctx->platPort = TestSocketPort(ctx->io.platListenFd);
    cmdClient = TestConnectLoopback(ctx->cmdPort);
    platClient = TestConnectLoopback(ctx->platPort);
    if (cmdClient < 0 || platClient < 0) {
        rc = TPM_RC_FAILURE;
    }
    if (rc == TPM_RC_SUCCESS) {
        gCmdNoDelay = -1;
        gPlatNoDelay = -1;
        gSelectPolls = 0;
        gSelectCtx = ctx;
        rc = FWTPM_IO_ServerLoop(ctx);
        gSelectCtx = NULL;
        g_stopRequested = 0;
        *cmdNoDelay = gCmdNoDelay;
        *platNoDelay = gPlatNoDelay;
    }

    if (platClient >= 0) {
        (void)close(platClient);
    }
    if (cmdClient >= 0) {
        (void)close(cmdClient);
    }
    FWTPM_IO_Cleanup(ctx);
    return rc;
}
#endif /* !_WIN32 */
