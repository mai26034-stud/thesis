#include "kem.h"
#include "kem_internal.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    WC_RNG rng;
} x25519_ctx_t;

static kem_status_t x25519_keypair(const kem_t *, uint8_t *, uint8_t *);
static kem_status_t x25519_encaps(const kem_t *, const uint8_t *, uint8_t *, uint8_t *);
static kem_status_t x25519_decaps(const kem_t *, const uint8_t *, const uint8_t *, uint8_t *);
void kem_x25519_close(kem_t *);

kem_t *kem_x25519_open(const char *name){
        kem_t *k = malloc(sizeof(kem_t));
        if(k == NULL) return NULL;
        x25519_ctx_t *ctx = malloc(sizeof(x25519_ctx_t));
        if(ctx == NULL){
                free(k);
                return NULL;
        }
        if(wc_InitRng(&ctx->rng) != 0){
            free(ctx);
            free(k);
            return NULL;
        }
        k->pk_len = 32;
        k->sk_len = 64;
        k->ct_len = 32;
        k->ss_len = 32;
        k->name = "X25519";
        k->nist_lvl = 1;
        k->backend = ctx;
        k->keypair = x25519_keypair;
        k->encaps = x25519_encaps;
        k->decaps = x25519_decaps;
        k->close = kem_x25519_close;
        return k;
}

void kem_x25519_close(kem_t *k){
    if(k == NULL) return;
    x25519_ctx_t *ctx = (x25519_ctx_t *)k->backend;
    wc_FreeRng(&ctx->rng);
    free(ctx);
    free(k);
}

static kem_status_t x25519_keypair(const kem_t *k, uint8_t *pk, uint8_t *sk){
    x25519_ctx_t *ctx = (x25519_ctx_t *)k->backend;
    curve25519_key key;
    wc_curve25519_init(&key);
    int ret = wc_curve25519_make_key(&ctx->rng, 32, &key);
    if(ret != 0){
        wc_curve25519_free(&key);
        return KEM_ERROR;
    }
    word32 pub_len = 32;
    ret = wc_curve25519_export_public_ex(&key, pk, &pub_len, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&key);
        return KEM_ERROR;
    }
    word32 priv_len = 32;
    ret = wc_curve25519_export_private_raw_ex(&key, sk, &priv_len, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&key);
        return KEM_ERROR;
    }
    memcpy(sk + 32, pk, 32);
    wc_curve25519_free(&key);
    return KEM_SUCCESS;
}

static kem_status_t x25519_encaps(const kem_t *k, const uint8_t *pk, uint8_t *ct, uint8_t *ss){
    curve25519_key eph;
    curve25519_key peer;
    x25519_ctx_t *ctx = (x25519_ctx_t*)k->backend;
    wc_curve25519_init(&eph);
    wc_curve25519_init(&peer);
    int ret = wc_curve25519_make_key(&ctx->rng, 32, &eph);
    if(ret != 0){
        wc_curve25519_free(&eph);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    ret = wc_curve25519_import_public_ex(pk, 32, &peer, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&eph);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    word32 ct_len = 32;
    ret = wc_curve25519_export_public_ex(&eph, ct, &ct_len, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&eph);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    word32 ss_len = 32;
    ret = wc_curve25519_shared_secret(&eph, &peer, ss, &ss_len);
    if(ret != 0){
        wc_curve25519_free(&eph);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    wc_curve25519_free(&eph);
    wc_curve25519_free(&peer);
    return KEM_SUCCESS;
}

static kem_status_t x25519_decaps(const kem_t *k, const uint8_t *sk, const uint8_t *ct, uint8_t *ss){
    curve25519_key mine;
    curve25519_key peer;
    x25519_ctx_t *ctx = (x25519_ctx_t*)k->backend;
    wc_curve25519_init(&mine);
    wc_curve25519_init(&peer);
    int ret = wc_curve25519_import_private_ex(sk, 32, &mine, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&mine);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    ret = wc_curve25519_set_rng(&mine, &ctx->rng);
    if(ret != 0){
        wc_curve25519_free(&mine);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    ret = wc_curve25519_import_public_ex(ct, 32, &peer, EC25519_LITTLE_ENDIAN);
    if(ret != 0){
        wc_curve25519_free(&mine);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    word32 ss_len = 32;
    ret = wc_curve25519_shared_secret(&mine, &peer, ss, &ss_len);
    if(ret != 0){
        wc_curve25519_free(&mine);
        wc_curve25519_free(&peer);
        return KEM_ERROR;
    }
    wc_curve25519_free(&mine);
    wc_curve25519_free(&peer);
    return KEM_SUCCESS;
}