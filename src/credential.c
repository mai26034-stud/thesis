#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/memory.h>
#include "credential.h"
#include <string.h>
#include <stdio.h>

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
    if(wc_ed25519_make_public(&key, pub, ED25519_PUB_LEN) != 0){
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    if(wc_ed25519_import_private_key(ca_priv, ED25519_PRIV_LEN, pub, ED25519_PUB_LEN, &key) != 0){
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

kem_status_t credential_verify(const uint8_t *cred, size_t cred_len, const uint8_t *ca_pub, const uint8_t **kem_pk_out, size_t *kem_pk_len_out){
    if(cred == NULL || ca_pub == NULL || kem_pk_out == NULL || kem_pk_len_out == NULL) return KEM_ERROR;
    if(cred_len < 68){
        printf("cv: too short (%zu)\n", cred_len);
        return KEM_ERROR;
    }
    size_t identity_len = ((size_t)cred[0] <<8) | (size_t)cred[1];
    size_t pos = 2 + identity_len;
    if(pos + 2 > cred_len){
        printf("cv: identity overflow (id_len=%zu cred_len=%zu)\n", identity_len, cred_len);
        return KEM_ERROR;
    }
    size_t kem_pk_len = ((size_t)cred[pos] <<8) | (size_t)cred[pos + 1];
    pos += 2;
    const uint8_t *kem_pk = cred + pos;
    pos += kem_pk_len;
    if(pos + ED25519_SIG_LEN > cred_len){ 
        printf("cv: pk overflow (pk_len=%zu pos=%zu cred_len=%zu)\n", kem_pk_len, pos, cred_len);
        return KEM_ERROR;
    }
    ed25519_key key;
    if(wc_ed25519_init(&key) != 0) return KEM_ERROR;
    if(wc_ed25519_import_public(ca_pub, ED25519_PUB_LEN, &key) != 0){
        printf("cv import failed :(\n");
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    int res = 0;
    int rc = wc_ed25519_verify_msg(cred + pos, ED25519_SIG_LEN, cred, (word32)pos, &res, &key);
    if(rc != 0 || res != 1){
        printf("cv: verify rc=%d es=%d\n", rc, res);
        wc_ed25519_free(&key);
        return KEM_ERROR;
    }
    *kem_pk_out = kem_pk;
    *kem_pk_len_out = kem_pk_len;
    wc_ed25519_free(&key);
    return KEM_SUCCESS;
}