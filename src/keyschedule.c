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

static kem_status_t empty_hash(uint8_t *out){
     uint8_t empty[1] = {0};
     return transcript_hash(empty, 0, out);
}

kem_status_t derive_handshake_secrets(const uint8_t *ss_ephemeral, size_t ss_eph_len, const uint8_t *ss_auth, size_t ss_auth_len, uint8_t *main_secret_out){
     if(main_secret_out == NULL) return KEM_ERROR;
     ks_state_t st;
     kem_status_t r = ks_stage_handshake(&st, ss_ephemeral, ss_eph_len);
     if(r != KEM_SUCCESS){
          ks_state_clear(&st);
          return KEM_ERROR;
     }
     r = ks_stage_auth(&st, ss_auth, ss_auth_len);
     if(r != KEM_SUCCESS){
          ks_state_clear(&st);
          return KEM_ERROR;
     }
     memcpy(main_secret_out, st.ms, 32);
     ks_state_clear(&st);
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
     uint8_t zeros[32] = {0};
     uint8_t dhs[32], th0[32], dahs[32];
     kem_status_t r = empty_hash(th0);
     if(r != KEM_SUCCESS) return KEM_ERROR;
     r = ks_derive_secret(st->hs, "derived", th0, dhs);
     if(r != KEM_SUCCESS){
          wc_ForceZero(dhs, 32);
          wc_ForceZero(dahs, 32);
          return KEM_ERROR;
     }
     r = ks_extract(dhs, 32, ss_auth, ss_auth_len, st->ahs);
     if(r != KEM_SUCCESS){
          wc_ForceZero(dhs, 32);
          wc_ForceZero(dahs, 32);
          return KEM_ERROR;
     }
     r = ks_derive_secret(st->ahs, "derived", th0, dahs);
     if(r != KEM_SUCCESS){
          wc_ForceZero(dhs, 32);
          wc_ForceZero(dahs, 32);
          return KEM_ERROR;
     }
     r = ks_extract(dahs, 32, zeros, 32, st->ms);
     if(r != KEM_SUCCESS){
          wc_ForceZero(dhs, 32);
          wc_ForceZero(dahs, 32);
          return KEM_ERROR;
     }
     wc_ForceZero(dhs, 32);
     wc_ForceZero(dahs, 32);
     return KEM_SUCCESS;
}

void ks_state_clear(ks_state_t *st){
     if(st == NULL) return;
     wc_ForceZero(st, sizeof(*st));
}
