#include "credential.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <string.h>
#include <wolfssl/wolfcrypt/hash.h>

kem_status_t credential_create(const uint8_t *identity, size_t identity_len, const uint8_t *kem_pk, size_t kem_pk_len, const uint8_t *ca_priv, const uint8_t *ca_pub, uint8_t *out, size_t out_cap, size_t *written){
    if(identity == NULL || kem_pk == NULL || ca_priv == NULL || ca_pub == NULL || out == NULL || written == NULL) return KEM_ERROR;
    if(identity_len > CRED_MAX_IDENTITY || identity_len == 0) return KEM_ERROR;
    if(kem_pk_len == 0 || kem_pk_len > CRED_MAX_KEM_PK) return KEM_ERROR;
    size_t tbs_len = 2 + identity_len + 2 + kem_pk_len;
    if(out_cap < tbs_len + 2 + CA_SIG_MAX) return KEM_ERROR;
    size_t pos = 0;
    out[pos++] = (uint8_t)(identity_len >> 8);
    out[pos++] = (uint8_t)(identity_len & 0xFF);
    memcpy(out + pos, identity, identity_len);
    pos += identity_len;
    out[pos++] = (uint8_t)(kem_pk_len >> 8);
    out[pos++] = (uint8_t)(kem_pk_len & 0xFF);
    memcpy(out + pos, kem_pk, kem_pk_len);
    pos += kem_pk_len;
    uint8_t digest[32];
    if(wc_Sha256Hash(out, (word32)tbs_len, digest) != 0) return KEM_ERROR;
    WC_RNG rng;
    ecc_key key;
    uint8_t sig[CA_SIG_MAX];
    word32 sig_len = CA_SIG_MAX;
    if(wc_InitRng(&rng) != 0) return KEM_ERROR;
    if(wc_ecc_init(&key) != 0){
        wc_FreeRng(&rng);
        return KEM_ERROR;
    }
    int ret = wc_ecc_import_private_key(ca_priv, CA_PRIV_LEN, ca_pub, CA_PUB_LEN, &key);
    if(ret == 0) ret = wc_ecc_sign_hash(digest, 32, sig, &sig_len, &rng, &key);
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    if(ret != 0 || sig_len == 0 || sig_len > CA_SIG_MAX) return KEM_ERROR;
    out[pos++] = (uint8_t)(sig_len >> 8);
    out[pos++] = (uint8_t)(sig_len & 0xFF);
    memcpy(out + pos, sig, sig_len);
    pos += sig_len;
    *written = pos;
    return KEM_SUCCESS;
}

kem_status_t ca_keygen(uint8_t *ca_pub, uint8_t *ca_priv){
    if(ca_pub == NULL || ca_priv == NULL) return KEM_ERROR;
    WC_RNG rng;
    ecc_key key;
    word32 pub_len = CA_PUB_LEN;
    word32 priv_len = CA_PRIV_LEN;
    if(wc_InitRng(&rng) != 0) return KEM_ERROR;
    if(wc_ecc_init(&key) != 0){
        wc_FreeRng(&rng);
        return KEM_ERROR;
    }
    int ret = wc_ecc_make_key_ex(&rng, 32, &key, ECC_SECP256R1);
    if(ret == 0) ret = wc_ecc_export_x963(&key, ca_pub, &pub_len);
    if(ret == 0) ret = wc_ecc_export_private_only(&key, ca_priv, &priv_len);
    if(ret == 0 && (pub_len != CA_PUB_LEN || priv_len != CA_PRIV_LEN)) ret = -1;
    wc_ecc_free(&key);
    wc_FreeRng(&rng);
    if(ret != 0){
        wc_ForceZero(ca_priv, CA_PRIV_LEN);
        return KEM_ERROR;
    }
    return KEM_SUCCESS;
}

kem_status_t credential_verify(const uint8_t *cred, size_t cred_len, const uint8_t *ca_pub, const uint8_t **kem_pk_out, size_t *kem_pk_len_out){
    if(cred == NULL || ca_pub == NULL || kem_pk_out == NULL || kem_pk_len_out == NULL) return KEM_ERROR;
    if(cred_len < 2) return KEM_ERROR;
    size_t pos = 0;
    size_t identity_len = ((size_t)cred[0] << 8) | cred[1];
    pos += 2;
    if(identity_len == 0 || identity_len > CRED_MAX_IDENTITY || identity_len > cred_len - pos) return KEM_ERROR;
    pos += identity_len;
    if(cred_len - pos < 2) return KEM_ERROR;
    size_t kem_pk_len = ((size_t)cred[pos] << 8) | cred[pos + 1];
    pos += 2;
    if(kem_pk_len == 0 || kem_pk_len > CRED_MAX_KEM_PK || kem_pk_len > cred_len - pos) return KEM_ERROR;
    const uint8_t *kem_pk = cred + pos;
    pos += kem_pk_len;
    size_t tbs_len = pos;
    if(cred_len - pos < 2) return KEM_ERROR;
    size_t sig_len = ((size_t)cred[pos] << 8) | cred[pos + 1];
    pos += 2;
    if(sig_len == 0 || sig_len > CA_SIG_MAX || sig_len != cred_len - pos) return KEM_ERROR;
    const uint8_t *sig = cred + pos;
    uint8_t digest[32];
    if(wc_Sha256Hash(cred, (word32)tbs_len, digest) != 0) return KEM_ERROR;
    ecc_key key;
    if(wc_ecc_init(&key) != 0) return KEM_ERROR;
    int res = 0;
    int ret = wc_ecc_import_x963(ca_pub, CA_PUB_LEN, &key);
    if(ret == 0) ret = wc_ecc_verify_hash(sig, (word32)sig_len, digest, 32, &res, &key);
    wc_ecc_free(&key);
    if(ret != 0 || res != 1) return KEM_ERROR;
    *kem_pk_out = kem_pk;
    *kem_pk_len_out = kem_pk_len;
    return KEM_SUCCESS;
}