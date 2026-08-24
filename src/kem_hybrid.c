#include "kem.h"
#include "kem_internal.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#define PKM_LEN 1184
#define PKX_LEN 32
#define SKM_LEN 2400
#define SKX_FULL_LEN 64
#define CTM_LEN 1088
#define CTX_LEN 32
#define SS_LEN 32

typedef struct{
    kem_t *mlkem;
    kem_t *x25519;
} hybrid_ctx_t;

static const uint8_t XWING_LABEL[6] = {0x5c,0x2e,0x2f,0x2f,0x5e,0x5c};
static kem_status_t kem_hybrid_keygen(const kem_t *, uint8_t *, uint8_t *);
static kem_status_t kem_hybrid_encaps(const kem_t *, const uint8_t *, uint8_t *, uint8_t *);
static kem_status_t kem_hybrid_decaps(const kem_t *, const uint8_t *, const uint8_t *, uint8_t *);
void kem_hybrid_close(kem_t *);

static kem_status_t xwing_combiner(const uint8_t *ssM, const uint8_t *ssX, const uint8_t *ctX, const uint8_t *pkX, uint8_t *ss_out){
    wc_Sha3 cntxt;
    int ret = wc_InitSha3_256(&cntxt, NULL, INVALID_DEVID);
    if(ret != 0){
        wc_Sha3_256_Free(&cntxt);
        return KEM_ERROR;
    }
    ret = 0;
    if(wc_Sha3_256_Update(&cntxt, XWING_LABEL, 6)) ret++;
    if(wc_Sha3_256_Update(&cntxt, ssM, 32)) ret++;
    if(wc_Sha3_256_Update(&cntxt, ssX, 32)) ret++;
    if(wc_Sha3_256_Update(&cntxt, ctX, 32)) ret++;
    if(wc_Sha3_256_Update(&cntxt, pkX, 32)) ret++;
    if(wc_Sha3_256_Final(&cntxt, ss_out)) ret++;
    if(ret != 6){
         wc_Sha3_256_Free(&cntxt);
         return KEM_ERROR;
    }
    wc_Sha3_256_Free(&cntxt);
    return KEM_SUCCESS;
}

kem_t *kem_hybrid_open(const char *name){
    kem_t *k = malloc(sizeof(kem_t));
    if(k == NULL) return NULL;
    hybrid_ctx_t *ctx = malloc(sizeof(hybrid_ctx_t));
    if(ctx == NULL){
        free(k);
        return NULL;
    }
    ctx->mlkem = kem_open("ML-KEM-768");
    if(ctx->mlkem == NULL){
        free(ctx);
        free(k);
        return NULL;
    }
    ctx->x25519 = kem_open("X25519");
    if(ctx->x25519 == NULL){
        kem_close(ctx->mlkem);
        free(ctx);
        free(k);
        return NULL;
    }
    k->name = "X-Wing";
    k->pk_len = 1216;
    k->sk_len = 2464;
    k->ct_len = 1120;
    k->ss_len = 32;
    k->nist_lvl = 3;
    k->keypair = kem_hybrid_keygen;
    k->encaps = kem_hybrid_encaps;
    k->decaps = kem_hybrid_decaps;
    k->close = kem_hybrid_close;
    k->backend = ctx;
    return k;
}

static kem_status_t kem_hybrid_keygen(const kem_t *k, uint8_t *pk, uint8_t *sk){
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)k->backend;
    if(ctx == NULL) return KEM_ERROR;
    kem_status_t ret = kem_keypair(ctx->mlkem, pk, sk);
    if(ret != KEM_SUCCESS) return ret;
    ret = kem_keypair(ctx->x25519, pk + PKM_LEN, sk + SKM_LEN);
    if(ret != KEM_SUCCESS) return ret;
    return KEM_SUCCESS;
}

static kem_status_t kem_hybrid_encaps(const kem_t *k, const uint8_t *pk, uint8_t *ct, uint8_t *ss){
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)k->backend;
    if(ctx == NULL) return KEM_ERROR;
    uint8_t ssM[SS_LEN];
    uint8_t ssX[SS_LEN];
    kem_status_t ret = kem_encaps(ctx->mlkem, pk, ct, ssM);
    if(ret != KEM_SUCCESS) return KEM_ERROR;
    ret = kem_encaps(ctx->x25519, pk + PKM_LEN, ct + CTM_LEN, ssX);
    if(ret != KEM_SUCCESS){
        ForceZero(ssM, SS_LEN);
        return KEM_ERROR;
    }
    ret = xwing_combiner(ssM, ssX, ct + CTM_LEN, pk + PKM_LEN, ss);
    if(ret != KEM_SUCCESS){
        ForceZero(ssM, SS_LEN);
        ForceZero(ssX, SS_LEN);
        return KEM_ERROR;
    }
    ForceZero(ssM, SS_LEN);
    ForceZero(ssX, SS_LEN);
    return KEM_SUCCESS;
}

static kem_status_t kem_hybrid_decaps(const kem_t *k, const uint8_t *sk, const uint8_t *ct, uint8_t *ss){
    hybrid_ctx_t *ctx = (hybrid_ctx_t *)k->backend;
    if(ctx == NULL) return KEM_ERROR;
    uint8_t ssM[SS_LEN];
    uint8_t ssX[SS_LEN];
    kem_status_t ret = kem_decaps(ctx->mlkem, sk, ct, ssM);
    if(ret != KEM_SUCCESS){
        ForceZero(ssM, SS_LEN);
        return KEM_ERROR;
    }
    ret = kem_decaps(ctx->x25519, sk + SKM_LEN, ct + CTM_LEN, ssX);
    if(ret != KEM_SUCCESS){
        ForceZero(ssM, SS_LEN);
        ForceZero(ssX, SS_LEN);
        return KEM_ERROR;
    }
    ret = xwing_combiner(ssM, ssX, ct + CTM_LEN, sk + SKM_LEN + PKX_LEN, ss);
    if(ret != KEM_SUCCESS){
        ForceZero(ssM, SS_LEN);
        ForceZero(ssX, SS_LEN);
        return KEM_ERROR;
    }
    ForceZero(ssM, SS_LEN);
    ForceZero(ssX, SS_LEN);
    return KEM_SUCCESS;
}
