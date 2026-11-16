#ifndef BASELINE_H
#define BASELINE_H
#include <stdint.h>
#include <stddef.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "kem.h"
#include "metrics.h"

typedef struct{
    int fd;
    size_t bytes_sent;
    size_t bytes_recv;
}io_ctx_t;

typedef struct{
    WOLFSSL *ssl;
    io_ctx_t io;
}baseline_conn_t;

WOLFSSL_CTX *baseline_server_ctx(const char *cert_path, const char *key_path);
WOLFSSL_CTX *baseline_client_ctx(const char *ca_cert_path);
kem_status_t baseline_accept(WOLFSSL_CTX *ctx, int fd, baseline_conn_t *c, wire_stats_t *stats, timings_t *tm);
kem_status_t baseline_connect(WOLFSSL_CTX *ctx, int fd, baseline_conn_t *c, wire_stats_t *stats, timings_t *tm);
kem_status_t baseline_write(baseline_conn_t *c, const uint8_t *buf, size_t len);
kem_status_t baseline_read(baseline_conn_t *c, uint8_t *buf, size_t cap, size_t *n);
int baseline_pending(baseline_conn_t *c);
void baseline_free(baseline_conn_t *c);
#endif