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
#define WARMUP 3
#define ITERATIONS 30


static void print_hex(const char *label, const uint8_t *buf, size_t len){
    printf("%s: ", label);
    for(size_t i = 0; i < len; i++) printf("%02x", buf[i]);
    printf("\n");
}

static int one_handshake(const char *auth_kem_name, uint16_t port, const uint8_t *ca_pub, const uint8_t *cred, size_t cred_len, const uint8_t *srv_sk, int iteration){
    pid_t pid = fork();
    if(pid < 0) return 1;
    if(pid == 0){
        int fd = transport_server_accept(port);
        if(fd < 0) exit(1);
        uint8_t ms[32];
        wire_stats_t stats;
        wire_stats_init(&stats);
        timings_t tm;
        timings_init(&tm);
        kem_status_t r = handshake_server(fd, auth_kem_name, cred, cred_len, srv_sk, ms, &stats, &tm);
        if(r != KEM_SUCCESS){
            printf("Server unfortunately failed :(\n");
            transport_close(fd);
            exit(1);
        }
        if(iteration > 0) metrics_csv_row(stdout, auth_kem_name, "server", 1, &tm, &stats);
        transport_close(fd);
        exit(0);
    }

    int fd = -1;
    for(int attempt = 0; attempt < 50 && fd < 0; attempt++;){
        fd = transport_client_connect("127.0.0.1", port);
        if(fd < 0) usleep(10000);
    }
    if(fd < 0){
        waitpid(pid, NULL, 0);
        return 1;
    }
    uint8_t ms[32];
    wire_stats_t stats;
    wire_stats_init(&stats);
    int ok = 0;
    timings_t tm;
    timings_init(&tm);
    int ok = 0;
    if(handshake_client(fd, auth_kem_name, ca_pub, ms, &stats, &tm) != KEM_SUCCESS){
        printf("  The client unfortunately failed :(\n");
        ok = 1;
    } else if(iteration > 0){
        metrics_csv_row(stdout, auth_kem_name, "client", iteration, &tm, &stats);
    }
    transport_close(fd);
    waitpid(pid, NULL, 0);
    return ok;
}

static int run_handshake(const char *auth_kem_name, uint16_t port){
    uint8_t ca_pub[ED25519_PUB_LEN];
    uint8_t ca_priv[ED25519_PRIV_LEN];
    if(ca_keygen(ca_pub, ca_priv) != KEM_SUCCESS) return 1;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL) return 1;
    uint8_t *srv_pk = malloc(kem_pk_len(auth));
    uint8_t *srv_sk = malloc(kem_sk_len(auth));
    if(kem_keypair(auth, srv_pk, srv_sk) != KEM_SUCCESS) return 1;
    uint8_t cred[16384];
    size_t cred_len;
    const uint8_t identity[] = "test-server";
    if(credential_create(identity, 11, srv_pk, kem_pk_len(auth), ca_priv, cred, sizeof(cred), &cred_len) != KEM_SUCCESS) return 1;
    kem_close(auth);
    return 0;
}

int main(void){
    int failures = 0;
    metrics_csv_header(stdout);
    failures += run_handshake("ML-KEM-768", 19001);
    failures += run_handshake("HQC-3", 19002);
    failures += run_handshake("X-Wing", 19003);
    return failures;
}
