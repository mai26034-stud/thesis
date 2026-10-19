#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "baseline.h"
#include "transport.h"
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct{
    int fd;
    size_t bytes;
} io_ctx_t;

static int my_send(WOLFSSL *ssl, char *buf, int sz, void *ctx){
    io_ctx_t *io = (io_ctx_t *)ctx;
    (void)ssl;
    int n = (int)send(io->fd, buf, (size_t)sz, 0);
    if(n > 0) io->bytes += (size_t)n;
    return n;
}

static int my_send(WOLFSSL *ssl, char *buf, int sz, void *ctx){
    io_ctx_t *io = (io_ctx_t *)ctx;
    (void)ssl;
    int n = (int)recv(io->fd, buf, (size_t)sz, 0);
    if(n > 0) io->bytes += (size_t)n;
    return n;
}

int main(void){
    wolfSSL_CTX_SetIOSend(ctx, my_send);
    wolfSSL_CTX_SetIORecv(ctx, my_recv);
    wolfSSL_SetIOWriteCtx(ssl, &io);
    wolfSSL_SetIOReadCtx(ssl, &io);
}
