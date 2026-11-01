#include "kem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t alice_priv[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t alice_pub[32] = {
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};

static const uint8_t bob_priv[32] = {
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
    0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
    0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};

static const uint8_t bob_pub[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t shared_k[32] = {
    0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
    0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
    0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
    0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

static int run_tamper_test(void);
static int run_roundtrip(const char *name);
static int run_x25519_rfc7748(void);

int main(){
    const char *algorithms[] = { "ML-KEM-768", "HQC-3", "X25519", "X-Wing"};
    size_t n = sizeof(algorithms)/sizeof(algorithms[0]);
    int failures = 0;
    for(size_t i = 0; i < n; i++){
        if(run_roundtrip(algorithms[i]) != 0) failures++;
    }
    if(run_tamper_test() != 0) failures++;
    if(run_x25519_rfc7748() != 0) failures++;
    return failures;
}

static int run_roundtrip(const char *name){
    kem_t *k = kem_open(name);
    if(k == NULL) return 1;
    printf("All is good\n");
   
    uint8_t *pk = malloc(kem_pk_len(k));
    uint8_t *sk = malloc(kem_sk_len(k));
    uint8_t *ct = malloc(kem_ct_len(k));
    uint8_t *ss1 = malloc(kem_ss_len(k));
    uint8_t *ss2 = malloc(kem_ss_len(k));
    
    if(pk == NULL || sk == NULL || ct == NULL || ss1 == NULL || ss2 == NULL){
             free(pk);
             free(sk);
             free(ct);
             free(ss1);
             free(ss2);
             printf("Some malloc failed\n");
             return 1;
    }

    kem_status_t r1 = kem_keypair(k, pk, sk);
    kem_status_t r2 = kem_encaps(k, pk, ct, ss1);
    kem_status_t r3 = kem_decaps(k, sk, ct, ss2);

    if(r1 != KEM_SUCCESS || r2 != KEM_SUCCESS || r3 != KEM_SUCCESS){
        printf("[%s] operation FAILED: r1=%d r2=%d r3=%d\n", name, r1, r2, r3);
        free(pk);
        free(sk);
        free(ct);
        free(ss1);
        free(ss2);
        kem_close(k);
        return 1;
    }

    if(memcmp(ss1, ss2, kem_ss_len(k)) == 0){
        printf("[%s] ROUNDTRIP OK: shared secrets do in fact match :)\n", name);
    } else{
        printf("ROUNDTRIP FAILED: The secrets do not in fact match :(\n");
        return 1;
    }
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    kem_close(k);
    return 0;
}

static int run_tamper_test(void){
    kem_t *k = kem_open("X-Wing");
    if(k == NULL) return 1;

    uint8_t *pk = malloc(kem_pk_len(k));
    uint8_t *sk = malloc(kem_sk_len(k));
    uint8_t *ct = malloc(kem_ct_len(k));
    uint8_t *ss1 = malloc(kem_ss_len(k));
    uint8_t *ss2 = malloc(kem_ss_len(k));

    kem_keypair(k, pk, sk);
    kem_encaps(k, pk, ct, ss1);

    ct[1088] ^= 1;

    kem_decaps(k, sk, ct, ss2);

    int ok;
    if(memcmp(ss1, ss2, kem_ss_len(k)) != 0){
        printf("[X-Wing] TAMPER TEST OK: altering ctX did in fact change the shared secret :)\n");
        ok = 0;
    }else{
        printf("[X-Wing] TAMPER TEST FAILED: shared secret was not impacted despite the tampering :(\n");
        ok = 1;
    }
    free(pk);
    free(sk);
    free(ct);
    free(ss1);
    free(ss2);
    kem_close(k);

    return ok;
}

static int run_x25519_rfc7748(){
    kem_t *k = kem_open("X25519");
    if(k == NULL) return 1;
    uint8_t sk[64];
    uint8_t ss[32];
    int ok = 0;
    memcpy(sk, alice_priv, 32);
    memcpy(sk + 32, alice_pub, 32);
    kem_status_t r = kem_decaps(k, sk, bob_pub, ss);
    if(r != KEM_SUCCESS){
        printf("Alice could not call successfully..\n");
        ok = 1;
    }else if(memcmp(ss, shared_k, 32) != 0){
        printf("K found by Alice is incorrect :(\n");
        ok = 1;
    }
    memcpy(sk, bob_priv, 32);
    memcpy(sk + 32, bob_pub, 32);
    r = kem_decaps(k, sk, alice_pub, ss);
    if(r != KEM_SUCCESS){
        printf("Bob could not call successfully..\n");
        ok = 1;
    }else if(memcmp(ss, shared_k, 32) != 0){
        printf("K found by Bob is incorrect :(\n");
        ok = 1;
    }
    if(ok == 0) printf("[X25519] RFC 7748 IS OK :)\n");
    kem_close(k);
    return ok;
}