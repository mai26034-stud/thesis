#include "keyschedule.h"
#include "kem.h"
#include "kem_internal.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <string.h>
#include <stdint.h>

static const char TLS13_PREFIX[6] = {'t', 'l', 's', '1', '3', ' '};
kem_status_t ks_expand_label(const uint8_t *secret, const char *label, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len){
     if(secret == NULL || label == NULL || out == NULL) return KEM_ERROR;
     if(context == NULL && context_len > 0) return KEM_ERROR;
     if(6 + strlen(label) > 255 || context_len > 255) return KEM_ERROR;
     uint8_t hkdf_label[514];
     size_t pos = 0;

     hkdf_label[pos++] = (uint8_t)(out_len >> 8);
     hkdf_label[pos++] = (uint8_t)(out_len & 0xFF);

     size_t label_len = strlen(label);
     hkdf_label[pos++] = (uint8_t)(6 + label_len);

     memcpy(hkdf_label + pos, TLS13_PREFIX, 6);
     pos +=6;

     memcpy(hkdf_label + pos, label, label_len);
     pos += label_len;

     hkdf_label[pos++] = (uint8_t)context_len;
     if(context_len > 0){
          memcpy(hkdf_label + pos, context, context_len);
          pos += context_len;
     }

     int ret = wc_HKDF_Expand(WC_SHA256, secret, 32, hkdf_label, (word32)pos, out, (word32)out_len);
     if(ret != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

static kem_status_t transcript_hash(const uint8_t *msgs, size_t msgs_len, uint8_t *out){
     wc_Sha256 sha;
     int ret = wc_InitSha256(&sha);
     if(ret != 0) return KEM_ERROR;

     ret = wc_Sha256Update(&sha, msgs, (word32)msgs_len);
     if(ret != 0) return KEM_ERROR;

     ret = wc_Sha256Final(&sha, out);
     if(ret != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

static kem_status_t derive_secret(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *msgs, size_t msgs_len, uint8_t *out){
     uint8_t ctx_hash[32];
     int ret = transcript_hash(msgs, msgs_len, ctx_hash);
     if(ret != 0) return KEM_ERROR;

     ret = ks_expand_label(secret, label, ctx_hash, 32, out, 32);
     if(ret != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t derive_handshake_secrets(const uint8_t *ss_ephemeral, size_t ss_eph_len, const uint8_t *ss_auth, size_t ss_auth_len, uint8_t *main_secret_out){
     uint8_t zeros[32] = {0};
     uint8_t empty[1] = {0};
     uint8_t early_secret[32];
     uint8_t dES[32];
     uint8_t handshake_secret[32];
     uint8_t dHS[32];
     uint8_t auth_handshake_secret[32];
     uint8_t dAHS[32];
     int ret = wc_HKDF_Extract(WC_SHA256, zeros, 32, zeros, 32, early_secret);
     if(ret != 0) return KEM_ERROR;

     ret = derive_secret(early_secret, 32, "derived", empty, 0, dES);
     if(ret != 0) return KEM_ERROR;

     ret = wc_HKDF_Extract(WC_SHA256, dES, 32, ss_ephemeral, ss_eph_len, handshake_secret);
     if(ret != 0) return KEM_ERROR;

     ret = derive_secret(handshake_secret, 32, "derived", empty, 0, dHS);
     if(ret != 0) return KEM_ERROR;

     ret = wc_HKDF_Extract(WC_SHA256, dHS, 32, ss_auth, ss_auth_len, auth_handshake_secret);
     if(ret != 0) return KEM_ERROR;

     ret = derive_secret(auth_handshake_secret, 32, "derived", empty, 0, dAHS);
     if(ret != 0) return KEM_ERROR;

     ret = wc_HKDF_Extract(WC_SHA256, dAHS, 32, zeros, 32, main_secret_out);
     if(ret != 0) return KEM_ERROR;
     wc_ForceZero(early_secret, 32);
     wc_ForceZero(dES, 32);
     wc_ForceZero(handshake_secret, 32);
     wc_ForceZero(dHS, 32);
     wc_ForceZero(auth_handshake_secret, 32);
     wc_ForceZero(dAHS, 32);
     return KEM_SUCCESS;
}

kem_status_t ks_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *out){
     if(ikm == NULL || out == NULL) return KEM_ERROR;
     int r = wc_HKDF_Extract(WC_SHA256, salt, (word32)salt_len, ikm, (word32)ikm_len, out);
     if(r != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t ks_derive_secret(const uint8_t *secret, const char *label, const uint8_t *th, uint8_t *out){
     if(th == NULL) return KEM_ERROR;
     return ks_expand_label(secret, label, th, 32, out, 32);
}

kem_status_t ks_traffic_keys(const uint8_t *traffic_secret, uint8_t *key, uint8_t *iv){
     if(traffic_secret == NULL || key == NULL || iv == NULL) return KEM_ERROR;
     kem_status_t r = ks_expand_label(traffic_secret, "key", NULL, 0, key, 16);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     r = ks_expand_label(traffic_secret, "iv", NULL, 0, iv, 12);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t ks_stage_handshake(ks_state_t *st, const uint8_t *ss_eph, size_t ss_eph_len){
     if(st == NULL || ss_eph == NULL) return KEM_ERROR;
     uint8_t zeros[32] = {0};
     uint8_t es[32], th0[32], des[32];
     kem_status_t r = ks_extract(zeros, 32, zeros, 32, es);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     r = empty_hash(th0);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     r = ks_derive_secret(es, "derived", th0, des);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     r = ks_extract(des, 32, ss_eph, ss_eph_len, st->hs);
     wc_ForceZero(es, 32);
     wc_ForceZero(des, 32);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t ks_stage_auth(ks_state_t *st, const uint8_t *ss_auth, size_t ss_auth_len){
     if(st == NULL || ss_auth == NULL) return KEM_ERROR;
     kem_status_t dhs = ks_derive_secret(st->hs, "derived", th0);
     if(dhs != KEM_SUCCESS) return KEM_ERROR;
     st->ahs = ks_extract(dhs, 32, ss_auth, ss_auth_len);
     dahs = ks_derive_secret(st->ahs, "derived", th0);
     st->ms = ks_extract(dahs, 32, zeros, 32);
     wc_ForceZero(dhs);
     wc_ForceZero(dahs);
     return KEM_SUCCESS;
}
