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

static int my_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx){
    io_ctx_t *io = (io_ctx_t *)ctx;
    (void)ssl;
    int n = (int)recv(io->fd, buf, (size_t)sz, 0);
    if(n > 0) io->bytes += (size_t)n;
    return n;
}

kem_status_t baseline_server(int fd, const char *cert_path, const char *key_path, uint8_t *key_out, size_t *bytes_out, timings_t *tm){
    if(cert_path == NULL || key_path == NULL || key_out == NULL || bytes_out == NULL || tm == NULL || fd < 0) return KEM_ERROR;
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if(ctx == NULL) return KEM_ERROR;
    if(wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    if(wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    wolfSSL_CTX_SetIOSend(ctx, my_send);
    wolfSSL_CTX_SetIORecv(ctx, my_recv);
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if(ssl == NULL){
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    io_ctx_t io;
    io.fd = fd;
    io.bytes = 0;
    wolfSSL_SetIOWriteCtx(ssl, &io);
    wolfSSL_SetIOReadCtx(ssl, &io);
    uint64_t t0 = metrics_now();
    int ret = wolfSSL_accept(ssl);
    tm->total_ns = metrics_now() - t0;
    if(ret != WOLFSSL_SUCCESS){
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    *bytes_out = io.bytes;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return KEM_SUCCESS;
}

kem_status_t baseline_client(int fd, const char *ca_cert_path, uint8_t *key_out, size_t *bytes_out, timings_t *tm){
    if(ca_cert_path == NULL || key_path == NULL || key_out == NULL || bytes_out == NULL || tm == NULL || fd < 0) return KEM_ERROR;
    wolfSSL_Init();
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if(ctx == NULL) return KEM_ERROR;
    if(wolfSSL_CTX_load_verify_locations(ctx, ca_cert_path, NULL) != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    wolfSSL_CTX_SetIOSend(ctx, my_send);
    wolfSSL_CTX_SetIORecv(ctx, my_recv);
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if(ssl == NULL){
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    io_ctx_t io;
    io.fd = fd;
    io.bytes = 0;
    wolfSSL_SetIOWriteCtx(ssl, &io);
    wolfSSL_SetIOReadCtx(ssl, &io);
    uint64_t t0 = metrics_now();
    int ret = wolfSSL_connect(ssl);
    tm->total_ns = metrics_now() - t0;
    if(ret != WOLFSSL_SUCCESS){
        wolfSSL_free(ssl);
        wolfSSL_CTX_free(ctx);
        return KEM_ERROR;
    }
    *bytes_out = io.bytes;
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return KEM_SUCCESS;
}
