#include "handshake.h"
#include "transport.h"
#include "transcript.h"
#include "keyschedule.h"
#include "kem_internal.h"
#include <string.h>
#include <stdlib.h>

static kem_status_t recv_message(int fd, uint8_t *buf, size_t buf_cap, uint8_t *type_out, const uint8_t **content_out, size_t *content_len_out, size_t *total_out){
    if(buf == NULL || type_out == NULL || content_out == NULL || content_len_out == NULL || total_out == NULL) return KEM_ERROR;
    if(transport_recv(fd, buf, 5) != KEM_SUCCESS) return KEM_ERROR;
    size_t content_len = ((size_t)buf[1] << 24) | ((size_t)buf[2] << 16) | ((size_t)buf[3] << 8) | ((size_t)buf[4]);
    if(5 + content_len > buf_cap) return KEM_ERROR;
    if(content_len > 0){
        if(transport_recv(fd, buf + 5, content_len) != KEM_SUCCESS) return KEM_ERROR;
    }
    size_t consumed;
    kem_status_t t = wire_read(buf, 5 + content_len, type_out, content_out, content_len_out, &consumed);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    *total_out = 5 + content_len;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_SERVER_HELLO) return KEM_ERROR;
    transcript_append(&tr, msgbuf, total);
    t = kem_decaps(eph, eph_sk, content, ss_eph);
    if(t != KEM_SUCCESS) return KEM_ERROR;
}

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats){
    kem_t *eph = kem_open(EPHEMERAL_KEM);
    if(eph == NULL) return KEM_ERROR;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL){
      kem_close(eph);
      return KEM_ERROR;
    }
    uint8_t eph_pk[kem_pk_len(eph)];
    uint8_t eph_sk[kem_sk_len(eph)];
    uint8_t ss_eph[32];
    uint8_t ss_auth[32];
    uint8_t msgbuf[4096];
    uint8_t type;
    const uint8_t *content;
    size_t content_len, total;
    transcript_t tr;
    transcript_init(&tr);

    size_t written;
    kem_status_t t = kem_keypair(eph, eph_pk, eph_sk);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_CLIENT_HELLO, eph_pk, kem_pk_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    transport_send(fd, msgbuf, written);
    transcript_append(&tr, msgbuf, written);
    return KEM_SUCCESS;
}

kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats){
    
}
