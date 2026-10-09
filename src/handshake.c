#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include "handshake.h"
#include "transport.h"
#include "transcript.h"
#include "keyschedule.h"
#include "kem_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#define CHK(x, msg) do { if((x) != KEM_SUCCESS){ printf("FAIL: %s\n", msg); return KEM_ERROR;} } while(0)

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
    return KEM_SUCCESS;
}

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats){
    kem_t *eph = kem_open(EPHEMERAL_KEM);
    if(eph == NULL) return KEM_ERROR;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL){
      kem_close(eph);
      return KEM_ERROR;
    }
    uint8_t *eph_pk = malloc(kem_pk_len(eph));
    uint8_t *eph_sk = malloc(kem_sk_len(eph));
    if(eph_pk == NULL || eph_sk == NULL){
        kem_close(eph);
        return KEM_ERROR;
    }
    uint8_t ss_eph[32];
    uint8_t ss_auth[32];
    uint8_t msgbuf[16384];
    uint8_t type;
    const uint8_t *content;
    size_t content_len, total;
    transcript_t tr;
    transcript_init(&tr);
    size_t written;
    kem_status_t t = kem_keypair(eph, eph_pk, eph_sk);
    CHK(t, "client: eph keypair");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_CLIENT_HELLO, eph_pk, kem_pk_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    CHK(t, "client: wire_write hello");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    transport_send(fd, msgbuf, written);
    transcript_append(&tr, msgbuf, written);
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    CHK(t, "client: recv ServerHello");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_SERVER_HELLO){
        printf("FAIL: client: wrong type %d\n", type);
        return KEM_ERROR;
    }
    transcript_append(&tr, msgbuf, total);
    t = kem_decaps(eph, eph_sk, content, ss_eph);
    CHK(t, "client: eph decaps");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    CHK(t, "client: recv cred");
    if(type != WIRE_SERVER_AUTH) return KEM_ERROR;
    const uint8_t *server_auth_pk;
    size_t server_auth_pk_len;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t = credential_verify(content, content_len, ca_pub, &server_auth_pk, &server_auth_pk_len);
    CHK(t, "client: credential_verify");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    uint8_t *auth_ct = malloc(kem_ct_len(auth));
    t = kem_encaps(auth, server_auth_pk, auth_ct, ss_auth);
    CHK(t, "client: auth encaps");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_CLIENT_AUTH, auth_ct, kem_ct_len(auth), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = derive_handshake_secrets(ss_eph, 32, ss_auth, 32, main_secret_out);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    wc_ForceZero(ss_eph, 32);
    wc_ForceZero(ss_auth, 32);
    wc_ForceZero(eph_sk, 64);
    kem_close(eph);
    kem_close(auth);
    free(auth_ct);
    free(eph_pk);
    free(eph_sk);
    return KEM_SUCCESS;
}

kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats){
    kem_t *eph = kem_open(EPHEMERAL_KEM);
    if(eph == NULL) return KEM_ERROR;
    kem_t *auth = kem_open(auth_kem_name);
    if(auth == NULL){
        kem_close(eph);
        return KEM_ERROR;
    }
    uint8_t *eph_ct = malloc(kem_ct_len(eph));
    if(eph_ct == NULL){
        kem_close(eph);
        kem_close(auth);
        return KEM_ERROR;
    }
    uint8_t ss_eph[32], ss_auth[32], msgbuf[16384];
    uint8_t type;
    const uint8_t *content;
    size_t content_len, total, written;
    transcript_t tr;
    transcript_init(&tr);
    kem_status_t t;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    CHK(t, "server: recv ClientHello");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_CLIENT_HELLO){
        printf("FAILURE: server is of wrong type :(");
        return KEM_ERROR;
    }
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS){
        printf("FAILURE: server: transcript :(");
        return KEM_ERROR;
    }
    t = kem_encaps(eph, content, eph_ct, ss_eph);
    CHK(t, "server: eph encaps");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_SERVER_HELLO, eph_ct, kem_ct_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    CHK(t, "server: wire_write_serverHello");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_SERVER_AUTH, cred, cred_len, msgbuf, sizeof(msgbuf), &written, stats);
    CHK(t, "server: wire_write cred");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    CHK(t, "server: recv auth ct");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_CLIENT_AUTH){
        printf("FAILURE: server: wrong type :(");
        return KEM_ERROR;
    }
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t = kem_decaps(auth, auth_sk, content, ss_auth);
    printf("server: auth decaps :(");
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = derive_handshake_secrets(ss_eph, 32, ss_auth, 32, main_secret_out);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    wc_ForceZero(ss_auth, 32);
    wc_ForceZero(ss_eph, 32);
    kem_close(eph);
    kem_close(auth);
    free(eph_ct);
    return KEM_SUCCESS;
}
