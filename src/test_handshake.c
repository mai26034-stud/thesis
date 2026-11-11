#include "handshake.h"
#include "credential.h"
#include "transport.h"
#include "kem.h"
#include "kem_internal.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include "metrics.h"
#include "channel.h"
#define WARMUP 3
#define ITERATIONS 30

static int ping_client(int fd, record_dir_t *tx, record_dir_t *rx){
    const uint8_t ping[4] = {'p','i','n','g'};
    uint8_t buf[64];
    size_t n;
    uint8_t ct;
    if(channel_send(fd, tx, REC_TYPE_APPDATA, ping, 4, NULL) != KEM_SUCCESS) return 1;
    if(channel_recv(fd, rx, buf, sizeof(buf), &n, &ct) != KEM_SUCCESS) return 1;
    if(ct != REC_TYPE_APPDATA || n != 4 || memcmp(buf, "pong", 4) != 0) return 1;
    return 0;
}

static int ping_server(int fd, record_dir_t *tx, record_dir_t *rx){
    const uint8_t pong[4] = {'p','o','n','g'};
    uint8_t buf[64];
    size_t n;
    uint8_t ct;
    if(channel_recv(fd, rx, buf, sizeof(buf), &n, &ct) != KEM_SUCCESS) return 1;
    if(ct != REC_TYPE_APPDATA || n != 4 || memcmp(buf, "ping", 4) != 0) return 1;
    if(channel_send(fd, tx, REC_TYPE_APPDATA, pong, 4, NULL) != KEM_SUCCESS) return 1;
    return 0;
}

static int one_handshake(const char *auth_kem_name, uint16_t port, const uint8_t *ca_pub, const uint8_t *cred, size_t cred_len, const uint8_t *srv_sk, int iteration){
    fflush(stdout);
    pid_t pid = fork();
    if(pid < 0) return 1;
    if(pid == 0){
        int fd = transport_server_accept(port);
        if(fd < 0) exit(1);
        record_dir_t app_tx, app_rx;
        wire_stats_t stats;
        wire_stats_init(&stats);
        timings_t tm;
        timings_init(&tm);
        kem_status_t r = handshake_server(fd, auth_kem_name, cred, cred_len, srv_sk, &app_tx, &app_rx, &stats, &tm);
        if(r != KEM_SUCCESS){
            fprintf(stderr, "[%s] Server handshake failed.\n", auth_kem_name);
            transport_close(fd);
            exit(1);
        }
        if(iteration > 0) metrics_csv_row(stdout, auth_kem_name, "server", iteration, &tm, &stats);
        if(ping_server(fd, &app_tx, &app_rx) != 0){
            fprintf(stderr, "[%s] Server ping/pong failed.\n", auth_kem_name);
            transport_close(fd);
            record_clear(&app_tx);
            record_clear(&app_rx);
            exit(1);
        }
        transport_close(fd);
        fflush(stdout);
        record_clear(&app_tx);
        record_clear(&app_rx);
        exit(0);
    }

    int fd = -1;
    for(int attempt = 0; attempt < 50 && fd < 0; attempt++){
        fd = transport_client_connect("127.0.0.1", port);
        if(fd < 0) usleep(10000);
    }
    if(fd < 0){
        waitpid(pid, NULL, 0);
        return 1;
    }
    record_dir_t app_tx, app_rx;
    wire_stats_t stats;
    wire_stats_init(&stats);
    int ok = 0;
    timings_t tm;
    timings_init(&tm);
    if(handshake_client(fd, auth_kem_name, ca_pub, &app_tx, &app_rx, &stats, &tm) != KEM_SUCCESS){
        fprintf(stderr, "[%s] Client handshake failed.\n", auth_kem_name);
        ok = 1;
    } else{
        if(iteration > 0) metrics_csv_row(stdout, auth_kem_name, "client", iteration, &tm, &stats);
        if(ping_client(fd, &app_tx, &app_rx) != 0){
            fprintf(stderr, "[%s] Client ping/pong failed.\n", auth_kem_name);
            ok = 1;
        }
    }
    transport_close(fd);
    record_clear(&app_tx);
    record_clear(&app_rx);
    int status;
    waitpid(pid, &status, 0);
    if(!WIFEXITED(status) || WEXITSTATUS(status) != 0){
        fprintf(stderr, "[%s] Server process failed.\n", auth_kem_name);
        ok = 1;
    }
    return ok;
}

static int run_handshake(const char *auth_kem_name, uint16_t port){
    uint8_t ca_pub[CA_PUB_LEN];
    uint8_t ca_priv[CA_PRIV_LEN];
    if(ca_keygen(ca_pub, ca_priv) != KEM_SUCCESS) return 1;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL) return 1;
    uint8_t *srv_pk = malloc(kem_pk_len(auth));
    uint8_t *srv_sk = malloc(kem_sk_len(auth));
    if(kem_keypair(auth, srv_pk, srv_sk) != KEM_SUCCESS) return 1;
    uint8_t cred[16384];
    size_t cred_len;
    const uint8_t identity[] = "test-server";
    if(credential_create(identity, 11, srv_pk, kem_pk_len(auth), ca_priv, ca_pub, cred, sizeof(cred), &cred_len) != KEM_SUCCESS) return 1;
    kem_close(auth);
    int failures = 0;
    for(int i = 0; i <WARMUP + ITERATIONS; i++){
        int iter = (i < WARMUP)? -1 : (i - WARMUP + 1);
        if(one_handshake(auth_kem_name, port + i, ca_pub, cred, cred_len, srv_sk, iter) != 0) failures++;
    }
    free(srv_pk);
    free(srv_sk);
    return failures;
}

int main(void){
    int failures = 0;
    metrics_csv_header(stdout);
    fflush(stdout);
    failures += run_handshake("ML-KEM-768", 19000);
    failures += run_handshake("HQC-3", 19200);
    failures += run_handshake("X-Wing", 19400);
    return failures;
}
