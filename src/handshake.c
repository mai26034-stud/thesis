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
#include "record.h"

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

static kem_status_t send_encrypted(int fd, record_dir_t *tx, uint8_t type, const uint8_t *content, size_t content_len, transcript_t *tr, wire_stats_t *stats){
    uint8_t plain[REC_MAX_PLAIN];
    uint8_t rec[REC_HDR_LEN + REC_MAX_PLAIN + 1 + REC_TAG_LEN];
    size_t plain_len, rec_len;
    kem_status_t r = wire_write(type, content, content_len, plain, sizeof(plain), &plain_len, NULL);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    r = transcript_append(tr, plain, plain_len);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    r = record_seal(tx, REC_TYPE_HANDSHAKE, plain, plain_len, rec, sizeof(rec), &rec_len);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    r = transport_send(fd, rec, rec_len);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    if(stats != NULL){
        stats->bytes_by_type[type] += rec_len;
        stats->total_bytes += rec_len;
    }
    return KEM_SUCCESS;
}

static kem_status_t recv_encrypted(int fd, record_dir_t *rx, uint8_t *buf, size_t buf_cap, uint8_t *type_out, const uint8_t **content_out, size_t *content_len_out, transcript_t *tr){
    uint8_t rec[REC_HDR_LEN + REC_MAX_PLAIN + 256];
    size_t plain_len, consumed;
    uint8_t ctype;
    kem_status_t r = transport_recv(fd, rec, REC_HDR_LEN);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    size_t body = ((size_t)rec[3] << 8) | rec[4];
    if(REC_HDR_LEN + body > sizeof(rec)) return KEM_ERROR;
    r = transport_recv(fd, rec + REC_HDR_LEN, body);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    r = record_open(rx, rec, REC_HDR_LEN + body, buf, buf_cap, &plain_len, &ctype);
    if(r != KEM_SUCCESS || ctype != REC_TYPE_HANDSHAKE) return KEM_ERROR;
    r = wire_read(buf, plain_len, type_out, content_out, content_len_out, &consumed);
    if(r != KEM_SUCCESS || consumed != plain_len) return KEM_ERROR;
    r = transcript_append(tr, buf, plain_len);
    if(r != KEM_SUCCESS) return KEM_ERROR;
    return KEM_SUCCESS;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t len){
    uint8_t diff = 0;
    for(size_t i = 0; i < len; i++){
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats, timings_t *tm){
    if(tm == NULL) return KEM_ERROR;
    uint64_t t0;
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
    uint64_t t_start = metrics_now();
    t0 = metrics_now();
    kem_status_t t = kem_keypair(eph, eph_pk, eph_sk);
    tm->eph_keypair_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_CLIENT_HELLO, eph_pk, kem_pk_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_SERVER_HELLO){
        fprintf(stderr, "FAIL: client: wrong type %d\n", type);
        return KEM_ERROR;
    }
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = kem_decaps(eph, eph_sk, content, ss_eph);
    tm->eph_decaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_SERVER_AUTH) return KEM_ERROR;
    const uint8_t *server_auth_pk;
    size_t server_auth_pk_len;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = credential_verify(content, content_len, ca_pub, &server_auth_pk, &server_auth_pk_len);
    tm->cred_verify_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(server_auth_pk_len != kem_pk_len(auth)) return KEM_ERROR;
    uint8_t *auth_ct = malloc(kem_ct_len(auth));
    if(auth_ct == NULL) return KEM_ERROR;
    t0 = metrics_now();
    t = kem_encaps(auth, server_auth_pk, auth_ct, ss_auth);
    tm->auth_encaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_CLIENT_AUTH, auth_ct, kem_ct_len(auth), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = derive_handshake_secrets(ss_eph, 32, ss_auth, 32, main_secret_out);
    tm->total_ns = metrics_now() - t_start;
    tm->key_schedule_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    wc_ForceZero(ss_eph, 32);
    wc_ForceZero(ss_auth, 32);
    wc_ForceZero(eph_sk, kem_sk_len(eph));
    kem_close(eph);
    kem_close(auth);
    free(auth_ct);
    free(eph_pk);
    free(eph_sk);
    return KEM_SUCCESS;
}

kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats, timings_t *tm){
    if(tm == NULL) return KEM_ERROR;
    uint64_t t0;
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
    uint64_t t_start = metrics_now();
    kem_status_t t;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_CLIENT_HELLO) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = kem_encaps(eph, content, eph_ct, ss_eph);
    tm->eph_encaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_SERVER_HELLO, eph_ct, kem_ct_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = wire_write(WIRE_SERVER_AUTH, cred, cred_len, msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) return KEM_ERROR;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) return KEM_ERROR;
    if(type != WIRE_CLIENT_AUTH) return KEM_ERROR;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = kem_decaps(auth, auth_sk, content, ss_auth);
    tm->auth_decaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    t0 = metrics_now();
    t = derive_handshake_secrets(ss_eph, 32, ss_auth, 32, main_secret_out);
    tm->total_ns = metrics_now() - t_start;
    tm->key_schedule_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) return KEM_ERROR;
    wc_ForceZero(ss_auth, 32);
    wc_ForceZero(ss_eph, 32);
    kem_close(eph);
    kem_close(auth);
    free(eph_ct);
    return KEM_SUCCESS;
}

