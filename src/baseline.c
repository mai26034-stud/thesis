#include "baseline.h"
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int my_send(WOLFSSL *ssl, char *buf, int sz, void *ctx){
    io_ctx_t *io = (io_ctx_t *)ctx;
    (void)ssl;
    int n = (int)send(io->fd, buf, (size_t)sz, 0);
    if(n > 0) io->bytes_sent += (size_t)n;
    return n;
}

static int my_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx){
    io_ctx_t *io = (io_ctx_t *)ctx;
    (void)ssl;
    int n = (int)recv(io->fd, buf, (size_t)sz, 0);
    if(n > 0) io->bytes_recv += (size_t)n;
    return n;
}

static WOLFSSL_CTX *common_ctx(WOLFSSL_METHOD *method){
    if(method == NULL) return NULL;
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(method);
    if(ctx == NULL) return NULL;
    int groups[1] = {WOLFSSL_ECC_X25519};
    if(wolfSSL_CTX_set_groups(ctx, groups, 1) != WOLFSSL_SUCCESS || wolfSSL_CTX_set_cipher_list(ctx, "TLS13-AES128-GCM-SHA256") != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    wolfSSL_CTX_SetIOSend(ctx, my_send);
    wolfSSL_CTX_SetIORecv(ctx, my_recv);
    return ctx;
}

WOLFSSL_CTX *baseline_server_ctx(const char *cert_path, const char *key_path){
    if(cert_path == NULL || key_path == NULL) return NULL;
    WOLFSSL_CTX *ctx = common_ctx(wolfTLSv1_3_server_method());
    if(ctx == NULL) return NULL;
    if(wolfSSL_CTX_use_certificate_file(ctx, cert_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS || wolfSSL_CTX_use_PrivateKey_file(ctx, key_path, WOLFSSL_FILETYPE_PEM) != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

WOLFSSL_CTX *baseline_client_ctx(const char *ca_cert_path){
    if(ca_cert_path == NULL) return NULL;
    WOLFSSL_CTX *ctx = common_ctx(wolfTLSv1_3_client_method());
    if(ctx == NULL) return NULL;
    if(wolfSSL_CTX_load_verify_locations(ctx, ca_cert_path, NULL) != WOLFSSL_SUCCESS){
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static kem_status_t conn_new(WOLFSSL_CTX *ctx, int fd, baseline_conn_t *c){
    if(ctx == NULL || c == NULL || fd < 0) return KEM_ERROR;
    c->io.fd = fd;
    c->io.bytes_sent = 0;
    c->io.bytes_recv = 0;
    c->ssl = wolfSSL_new(ctx);
    if(c->ssl == NULL) return KEM_ERROR;
    wolfSSL_SetIOWriteCtx(c->ssl, &c->io);
    wolfSSL_SetIOReadCtx(c->ssl, &c->io);
    return KEM_SUCCESS;
}

kem_status_t baseline_accept(WOLFSSL_CTX *ctx, int fd, baseline_conn_t *c, wire_stats_t *stats, timings_t *tm){
    if(stats == NULL || tm == NULL) return KEM_ERROR;
    if(conn_new(ctx, fd, c) != KEM_SUCCESS) return KEM_ERROR;
    uint64_t c0 = metrics_cpu_now();
    uint64_t t0 = metrics_now();
    int ret = wolfSSL_accept(c->ssl);
    tm->total_ns = metrics_now() - t0;
    tm->cpu_ns = metrics_cpu_now() - c0;
    if(ret != WOLFSSL_SUCCESS){
        baseline_free(c);
        return KEM_ERROR;
    }
    stats->total_bytes = c->io.bytes_sent;
    return KEM_SUCCESS;
}

kem_status_t baseline_connect(WOLFSSL_CTX *ctx, int fd, baseline_conn_t *c, wire_stats_t *stats, timings_t *tm){
    if(stats == NULL || tm == NULL) return KEM_ERROR;
    if(conn_new(ctx, fd, c) != KEM_SUCCESS) return KEM_ERROR;
    uint64_t c0 = metrics_cpu_now();
    uint64_t t0 = metrics_now();
    int ret = wolfSSL_connect(c->ssl);
    tm->total_ns = metrics_now() - t0;
    tm->cpu_ns = metrics_cpu_now() - c0;
    tm->client_ready_ns = tm->total_ns;
    if(ret != WOLFSSL_SUCCESS){
        baseline_free(c);
        return KEM_ERROR;
    }
    stats->total_bytes = c->io.bytes_sent;
    return KEM_SUCCESS;
}

kem_status_t baseline_write(baseline_conn_t *c, const uint8_t *buf, size_t len){
    if(c == NULL || c->ssl == NULL || buf == NULL || len == 0 || len > INT_MAX) return KEM_ERROR;
    int ret = wolfSSL_write(c->ssl, buf, (int)len);
    if(ret != (int)len) return KEM_ERROR;
    return KEM_SUCCESS;
}

kem_status_t baseline_read(baseline_conn_t *c, uint8_t *buf, size_t cap, size_t *n){
    if(c == NULL || c->ssl == NULL || buf == NULL || n == NULL || cap == 0 || cap > INT_MAX) return KEM_ERROR;
    int ret = wolfSSL_read(c->ssl, buf, (int)cap);
    if(ret <= 0) return KEM_ERROR;
    *n = (size_t)ret;
    return KEM_SUCCESS;
}

int baseline_pending(baseline_conn_t *c){
    if(c == NULL || c->ssl == NULL) return 0;
    return wolfSSL_pending(c->ssl);
}

void baseline_free(baseline_conn_t *c){
    if(c == NULL || c->ssl == NULL) return;
    wolfSSL_free(c->ssl);
    c->ssl = NULL;
}
