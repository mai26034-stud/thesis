#include "files.h"
#include "credential.h"
#include "kem.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *CONFIGS[] = {"ML-KEM-768", "HQC-3", "X-Wing"};
static const uint8_t IDENTITY[] = "gateway";

static int make_path(char *out, size_t cap, const char *dir, const char *name, const char *ext){
    int n = snprintf(out, cap, "%s/%s.%s", dir, name, ext);
    if(n <= 0 || (size_t)n >= cap) return 1;
    return 0;
}

static int provision_one(const char *dir, const char *name, const uint8_t *ca_priv, const uint8_t *ca_pub){
    kem_t *k = kem_open(name);
    if(k == NULL) return 1;
    uint8_t *pk = malloc(kem_pk_len(k));
    uint8_t *sk = malloc(kem_sk_len(k));
    uint8_t cred[6 + CRED_MAX_IDENTITY + CRED_MAX_KEM_PK + CA_SIG_MAX];
    size_t cred_len = 0;
    char path[512];
    kem_status_t r = (pk != NULL && sk != NULL) ? KEM_SUCCESS : KEM_ERROR;
    if(r == KEM_SUCCESS) r = kem_keypair(k, pk, sk);
    if(r == KEM_SUCCESS) r = credential_create(IDENTITY, sizeof(IDENTITY) - 1, pk, kem_pk_len(k), ca_priv, ca_pub, cred, sizeof(cred), &cred_len);
    if(r == KEM_SUCCESS && make_path(path, sizeof(path), dir, name, "cred") != 0) r = KEM_ERROR;
    if(r == KEM_SUCCESS) r = file_write(path, cred, cred_len);
    if(r == KEM_SUCCESS && make_path(path, sizeof(path), dir, name, "sk") != 0) r = KEM_ERROR;
    if(r == KEM_SUCCESS) r = file_write(path, sk, kem_sk_len(k));
    if(r == KEM_SUCCESS) printf("[provision] %s: cred %zu bytes, sk %zu bytes\n", name, cred_len, (size_t)kem_sk_len(k));
    if(sk != NULL) wc_ForceZero(sk, kem_sk_len(k));
    free(pk);
    free(sk);
    kem_close(k);
    return (r == KEM_SUCCESS) ? 0 : 1;
}

int main(int argc, char **argv){
    if(argc != 2){
        fprintf(stderr, "usage: %s <output_dir>\n", argv[0]);
        return 1;
    }
    const char *dir = argv[1];
    uint8_t ca_pub[CA_PUB_LEN];
    uint8_t ca_priv[CA_PRIV_LEN];
    char path[512];
    int failures = 0;
    if(ca_keygen(ca_pub, ca_priv) != KEM_SUCCESS){
        fprintf(stderr, "[provision] FAIL: CA keygen\n");
        return 1;
    }
    if(make_path(path, sizeof(path), dir, "ca", "pub") != 0 || file_write(path, ca_pub, CA_PUB_LEN) != KEM_SUCCESS){
        fprintf(stderr, "[provision] FAIL: ca.pub\n");
        failures++;
    }
    for(size_t i = 0; i < sizeof(CONFIGS)/sizeof(CONFIGS[0]); i++){
        if(provision_one(dir, CONFIGS[i], ca_priv, ca_pub) != 0){
            fprintf(stderr, "[provision] FAIL: %s\n", CONFIGS[i]);
            failures++;
        }
    }
    wc_ForceZero(ca_priv, CA_PRIV_LEN);
    if(failures == 0) printf("[provision] OK\n");
    return failures;
}