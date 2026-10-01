#include "handshake.h"
#include "transport.h"
#include "transcript.h"
#include "keyschedule.h"
#include "kem_internal.h"
#include <string.h>
#include <stdlib.h>

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats){
    kem_t *eph = kem_open(EPHEMERAL_KEM);
    if(eph == NULL) return KEM_ERROR;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL){
      kem_close(EPHEMERAL_KEM);
      return KEM_ERROR;
    }
    uint8_t eph_pk[kem_pk_len(eph)];
    uint8_t eph_sk[kem_sk_len(eph)];
    uint8_t ss_eph[32];
    uint8_t ss_auth[32];
    uint8_t msgbuf[4096];
    transcript_t tr;
    transcript_init(&tr);
}

kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats){
    size_t eph, eph_pk, eph_sk;
    kem_keypair(eph, eph_pk, eph_sk);
    kem_status_t t = wire_write(WIRE_CLIENT_HELLO, eph_pk, kem_pk_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t == NULL) return KEM_ERROR;
    transport_send(fd, msgbuf, written);
    transcript_append(&tr, msgbuf, written);
}
