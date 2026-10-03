#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "credential.h"
#include <string.h>

kem_status_t credential_create(const uint8_t *identity, size_t identity_len, const uint8_t *kem_pk, size_t kem_pk_len, const uint8_t *ca_priv, uint8_t *out, size_t out_cap, size_t *written){
    uint8_t pub[ED25519_PUB_LEN];
    if(identity == NULL || kem_pk == NULL || ca_priv == NULL || out == NULL || written == NULL) return KEM_ERROR;
    if(identity_len > CRED_MAX_IDENTITY || kem_pk_len > CRED_MAX_KEM_PK) return KEM_ERROR;
    if(2 + identity_len + 2 + kem_pk_len + ED25519_SIG_LEN > out_cap) return KEM_ERROR;
    size_t pos = 0;
    out[pos++] = (uint8_t)(identity_len >> 8);
    out[pos++] = (uint8_t)(identity_len & 0xFF);
    memcpy(out + pos, identity, identity_len);
    pos += identity_len;
    out[pos++] = (uint8_t)(kem_pk_len >> 8);
    out[pos++] = (uint8_t)(kem_pk_len & 0xFF);
    memcpy(out + pos, kem_pk, kem_pk_len);
    pos += kem_pk_len;
    ed25519_key key;
    if(wc_ed25519_init(&key) != 0) return KEM_ERROR;
    if(wc_ed25519_import_private_only(ca_priv, 32, &key) != 0){
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    if(wc_ed25519_make_public(&key, pub, 32) != 0){
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    word32 siglen = ED25519_SIG_LEN;
    if(wc_ed25519_sign_msg(out, (word32)pos, out + pos, &siglen, &key) != 0){
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    *written = pos + ED25519_SIG_LEN;
    wc_ed25519_free(&key);
    return KEM_SUCCESS;
}

kem_status_t ca_keygen(uint8_t *ca_pub, uint8_t *ca_priv){
    if(ca_pub == NULL || ca_priv == NULL) return KEM_ERROR;
    WC_RNG rng;
    ed25519_key key;
    if(wc_InitRng(&rng) != 0) return KEM_ERROR;
    if(wc_ed25519_init(&key) != 0){
        wc_FreeRng(&rng);
         return KEM_ERROR;
    }
    if(wc_ed25519_make_key(&rng, 32, &key) != 0){
        wc_ed25519_free(&key);
        wc_FreeRng(&rng);
        return KEM_ERROR;
    }
    word32 publen = ED25519_PUB_LEN;
    if(wc_ed25519_export_public(&key, ca_pub, &publen) != 0){
        wc_ed25519_free(&key);
        wc_FreeRng(&rng);
        return KEM_ERROR;
    }
    word32 privlen = ED25519_PRIV_LEN;
    if(wc_ed25519_export_private_only(&key, ca_priv, &privlen) != 0){
        wc_ed25519_free(&key);
        wc_FreeRng(&rng);
        return KEM_ERROR;
    }
    wc_ed25519_free(&key);
    wc_FreeRng(&rng);
    return KEM_SUCCESS;
}

kem_status_t credential_verify(const uint8_t *cred, size_t cred_len, const uint8_t *ca_pub, const uint8_t **kem_pk_out, size_t *kem_pk_len_out){}