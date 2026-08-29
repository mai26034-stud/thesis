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
static kem_status_t hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len){
     uint8_t hkdf_label[512];
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

     int ret = wc_HKDF_Expand(WC_SHA256, secret, (word32)secret_len, hkdf_label, (word32)pos, out, (word32)out_len); //να το ξαναδώ και επίσης ότι το WC_SHA256 είναι το σωστό όνομα
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

     ret = hkdf_expand_label(secret, secret_len, label, ctx_hash, 32, out, 32);
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
     return KEM_SUCCESS;  // Εκκρεμεί να ελεγχθεί ότι το WC_SHA256 είναι το σωστό όνομα μεταβλητής, ότι υπάρχουν τα wc_HKDF_Extract και wc_HKDF_Expand αλλιώς να τα ενεργοποιήσω, ότι η υπογραφή το wc_HKDF_Extract έχει την σωστή σειρά εισόδων και ότι το wc_InitSha256 παίρνει heap/devId εισόδους όπως το έχω.
}
