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
#include "channel.h"

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

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, const uint8_t *early_data, size_t early_len, record_dir_t *app_tx, record_dir_t *app_rx, wire_stats_t *stats, timings_t *tm){
    if(tm == NULL || app_tx == NULL || app_rx == NULL || (early_data == NULL && early_len > 0)) return KEM_ERROR;
    kem_status_t ret = KEM_ERROR;
    kem_status_t t;
    uint64_t t0, t_start, c_start;
    ks_state_t st;
    uint8_t th[32];
    uint8_t c_hs[32], s_hs[32], c_ahs[32], s_ahs[32], c_ap[32], s_ap[32], c_vd[32], s_vd[32];
    uint8_t ss_eph[32], ss_auth[32];
    uint8_t msgbuf[16384];
    record_dir_t hs_tx, hs_rx, ahs_tx, ahs_rx;
    transcript_t tr;
    int tr_ok = 0;
    uint8_t type;
    const uint8_t *content;
    size_t content_len, total, written;
    const uint8_t *server_auth_pk;
    size_t server_auth_pk_len;
    kem_t *eph = NULL;
    kem_t *auth = NULL;
    uint8_t *eph_pk = NULL;
    uint8_t *eph_sk = NULL;
    uint8_t *auth_ct = NULL;
    eph = kem_open(EPHEMERAL_KEM);
    auth = kem_open(auth_kem_name);
    if(eph == NULL || auth == NULL) goto cleanup;
    eph_pk = malloc(kem_pk_len(eph));
    eph_sk = malloc(kem_sk_len(eph));
    auth_ct = malloc(kem_ct_len(auth));
    if(eph_pk == NULL || eph_sk == NULL || auth_ct == NULL) goto cleanup;
    if(transcript_init(&tr) != KEM_SUCCESS) goto cleanup;
    tr_ok = 1;
    c_start = metrics_cpu_now();
    t_start = metrics_now();
    t0 = metrics_now();
    t = kem_keypair(eph, eph_pk, eph_sk);
    tm->eph_keypair_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = wire_write(WIRE_CLIENT_HELLO, eph_pk, kem_pk_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) goto cleanup;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) goto cleanup;
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) goto cleanup;
    if(type != WIRE_SERVER_HELLO || content_len != kem_ct_len(eph)) goto cleanup;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = kem_decaps(eph, eph_sk, content, ss_eph);
    tm->eph_decaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = ks_stage_handshake(&st, ss_eph, 32);
    if(t == KEM_SUCCESS) t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.hs, "c hs traffic", th, c_hs);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.hs, "s hs traffic", th, s_hs);
    if(t == KEM_SUCCESS) t = record_init(&hs_tx, c_hs);
    if(t == KEM_SUCCESS) t = record_init(&hs_rx, s_hs);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = recv_encrypted(fd, &hs_rx, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &tr);
    if(t != KEM_SUCCESS || type != WIRE_ENCRYPTED_EXTENSIONS || content_len != 0) goto cleanup;
    t = recv_encrypted(fd, &hs_rx, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &tr);
    if(t != KEM_SUCCESS || type != WIRE_SERVER_AUTH) goto cleanup;
    t0 = metrics_now();
    t = credential_verify(content, content_len, ca_pub, &server_auth_pk, &server_auth_pk_len);
    tm->cred_verify_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS || server_auth_pk_len != kem_pk_len(auth)) goto cleanup;
    t0 = metrics_now();
    t = kem_encaps(auth, server_auth_pk, auth_ct, ss_auth);
    tm->auth_encaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = send_encrypted(fd, &hs_tx, WIRE_CLIENT_AUTH, auth_ct, kem_ct_len(auth), &tr, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = ks_stage_auth(&st, ss_auth, 32);
    if(t == KEM_SUCCESS) t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ahs, "c ahs traffic", th, c_ahs);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ahs, "s ahs traffic", th, s_ahs);
    if(t == KEM_SUCCESS) t = record_init(&ahs_tx, c_ahs);
    if(t == KEM_SUCCESS) t = record_init(&ahs_rx, s_ahs);
    if(t == KEM_SUCCESS) t = ks_finished(st.ms, "client finished", th, c_vd);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = send_encrypted(fd, &ahs_tx, WIRE_FINISHED, c_vd, 32, &tr, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ms, "c ap traffic", th, c_ap);
    if(t == KEM_SUCCESS) t = record_init(app_tx, c_ap);
    if(t == KEM_SUCCESS) t = ks_finished(st.ms, "server finished", th, s_vd);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    tm->client_ready_ns = metrics_now() - t_start;
    if(early_len > 0){
        t = channel_send(fd, app_tx, REC_TYPE_APPDATA, early_data, early_len, NULL);
        if(t != KEM_SUCCESS) goto cleanup;
    }
    t = recv_encrypted(fd, &ahs_rx, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &tr);
    if(t != KEM_SUCCESS || type != WIRE_FINISHED || content_len != 32 || !ct_equal(content, s_vd, 32)) goto cleanup;
    t0 = metrics_now();
    t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ms, "s ap traffic", th, s_ap);
    if(t == KEM_SUCCESS) t = record_init(app_rx, s_ap);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    tm->total_ns = metrics_now() - t_start;
    tm->cpu_ns = metrics_cpu_now() - c_start;
    ret = KEM_SUCCESS;
cleanup:
    ks_state_clear(&st);
    if(tr_ok) transcript_free(&tr);
    wc_ForceZero(c_hs, 32);
    wc_ForceZero(s_hs, 32);
    wc_ForceZero(c_ahs, 32);
    wc_ForceZero(s_ahs, 32);
    wc_ForceZero(c_ap, 32);
    wc_ForceZero(s_ap, 32);
    wc_ForceZero(c_vd, 32);
    wc_ForceZero(s_vd, 32);
    wc_ForceZero(ss_eph, 32);
    wc_ForceZero(ss_auth, 32);
    record_clear(&hs_tx);
    record_clear(&hs_rx);
    record_clear(&ahs_tx);
    record_clear(&ahs_rx);
    if(ret != KEM_SUCCESS){
        record_clear(app_tx);
        record_clear(app_rx);
    }
    if(eph_sk != NULL) wc_ForceZero(eph_sk, kem_sk_len(eph));
    free(auth_ct);
    free(eph_pk);
    free(eph_sk);
    kem_close(eph);
    kem_close(auth);
    return ret;
}

kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, record_dir_t *app_tx, record_dir_t *app_rx, wire_stats_t *stats, timings_t *tm){
    if(tm == NULL || cred == NULL || auth_sk == NULL || app_tx == NULL || app_rx == NULL) return KEM_ERROR;
    kem_status_t ret = KEM_ERROR;
    kem_status_t t;
    uint64_t t0, t_start, c_start;
    ks_state_t st;
    uint8_t th[32];
    uint8_t c_hs[32], s_hs[32], c_ahs[32], s_ahs[32], c_ap[32], s_ap[32], c_vd[32], s_vd[32];
    uint8_t ss_eph[32], ss_auth[32];
    uint8_t msgbuf[16384];
    record_dir_t hs_tx, hs_rx, ahs_tx, ahs_rx;
    transcript_t tr;
    int tr_ok = 0;
    uint8_t type;
    const uint8_t *content;
    size_t content_len, total, written;
    kem_t *eph = NULL;
    kem_t *auth = NULL;
    uint8_t *eph_ct = NULL;
    eph = kem_open(EPHEMERAL_KEM);
    auth = kem_open(auth_kem_name);
    if(eph == NULL || auth == NULL) goto cleanup;
    eph_ct = malloc(kem_ct_len(eph));
    if(eph_ct == NULL) goto cleanup;
    if(transcript_init(&tr) != KEM_SUCCESS) goto cleanup;
    tr_ok = 1;
    c_start = metrics_cpu_now();
    t_start = metrics_now();
    t = recv_message(fd, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &total);
    if(t != KEM_SUCCESS) goto cleanup;
    if(type != WIRE_CLIENT_HELLO || content_len != kem_pk_len(eph)) goto cleanup;
    if(transcript_append(&tr, msgbuf, total) != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = kem_encaps(eph, content, eph_ct, ss_eph);
    tm->eph_encaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = wire_write(WIRE_SERVER_HELLO, eph_ct, kem_ct_len(eph), msgbuf, sizeof(msgbuf), &written, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    if(transport_send(fd, msgbuf, written) != KEM_SUCCESS) goto cleanup;
    if(transcript_append(&tr, msgbuf, written) != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = ks_stage_handshake(&st, ss_eph, 32);
    if(t == KEM_SUCCESS) t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.hs, "c hs traffic", th, c_hs);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.hs, "s hs traffic", th, s_hs);
    if(t == KEM_SUCCESS) t = record_init(&hs_tx, s_hs);
    if(t == KEM_SUCCESS) t = record_init(&hs_rx, c_hs);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = send_encrypted(fd, &hs_tx,  WIRE_ENCRYPTED_EXTENSIONS, NULL, 0, &tr, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    t = send_encrypted(fd, &hs_tx,  WIRE_SERVER_AUTH, cred, cred_len, &tr, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    t = recv_encrypted(fd, &hs_rx, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &tr);
    if(t != KEM_SUCCESS || type != WIRE_CLIENT_AUTH || content_len != kem_ct_len(auth)) goto cleanup;
    t0 = metrics_now();
    t = kem_decaps(auth, auth_sk, content, ss_auth);
    tm->auth_decaps_ns = metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = ks_stage_auth(&st, ss_auth, 32);
    if(t == KEM_SUCCESS) t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ahs, "c ahs traffic", th, c_ahs);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ahs, "s ahs traffic", th, s_ahs);
    if(t == KEM_SUCCESS) t = record_init(&ahs_tx, s_ahs);
    if(t == KEM_SUCCESS) t = record_init(&ahs_rx, c_ahs);
    if(t == KEM_SUCCESS) t = ks_finished(st.ms, "client finished", th, c_vd);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = recv_encrypted(fd, &ahs_rx, msgbuf, sizeof(msgbuf), &type, &content, &content_len, &tr);
    if(t != KEM_SUCCESS || type != WIRE_FINISHED || content_len != 32 || !ct_equal(content, c_vd, 32)) goto cleanup;
    t0 = metrics_now();
    t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ms, "c ap traffic", th, c_ap);
    if(t == KEM_SUCCESS) t = record_init(app_rx, c_ap);
    if(t == KEM_SUCCESS) t = ks_finished(st.ms, "server finished", th, s_vd);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    t = send_encrypted(fd, &ahs_tx, WIRE_FINISHED, s_vd, 32, &tr, stats);
    if(t != KEM_SUCCESS) goto cleanup;
    t0 = metrics_now();
    t = transcript_get_hash(&tr, th);
    if(t == KEM_SUCCESS) t = ks_derive_secret(st.ms, "s ap traffic", th, s_ap);
    if(t == KEM_SUCCESS) t = record_init(app_tx, s_ap);
    tm->key_schedule_ns += metrics_now() - t0;
    if(t != KEM_SUCCESS) goto cleanup;
    tm->total_ns = metrics_now() - t_start;
    tm->cpu_ns = metrics_cpu_now() - c_start;
    ret = KEM_SUCCESS;
cleanup:
    ks_state_clear(&st);
    if(tr_ok) transcript_free(&tr);
    wc_ForceZero(c_hs, 32);
    wc_ForceZero(s_hs, 32);
    wc_ForceZero(c_ahs, 32);
    wc_ForceZero(s_ahs, 32);
    wc_ForceZero(c_ap, 32);
    wc_ForceZero(s_ap, 32);
    wc_ForceZero(c_vd, 32);
    wc_ForceZero(s_vd, 32);
    record_clear(&hs_tx);
    record_clear(&hs_rx);
    record_clear(&ahs_tx);
    record_clear(&ahs_rx);
    if(ret != KEM_SUCCESS){
        record_clear(app_tx);
        record_clear(app_rx);
    }
    wc_ForceZero(ss_auth, 32);
    wc_ForceZero(ss_eph, 32);
    kem_close(eph);
    kem_close(auth);
    free(eph_ct);
    return ret;
}
