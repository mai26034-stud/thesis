#include "kem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(){
    kem_t *k = kem_open("HQC-3");
    if(k == NULL) return 1;
    printf("All is good\n");
   
    uint8_t *pk = malloc(kem_pk_len(k));
    uint8_t *sk = malloc(kem_sk_len(k));
    uint8_t *ct = malloc(kem_ct_len(k));
    uint8_t *ss1 = malloc(kem_ss_len(k));
    uint8_t *ss2 = malloc(kem_ss_len(k));
    
    if(pk == NULL || sk == NULL || ct == NULL || ss1 == NULL || ss2 == NULL){
             printf("Some malloc failed\n");
             return 1;
    }

    kem_status_t r1 = kem_keypair(k, pk, sk);
    kem_status_t r2 = kem_encaps(k, pk, ct, ss1);
    kem_status_t r3 = kem_decaps(k, sk, ct, ss2);

    if(r1 != KEM_SUCCESS || r2 != KEM_SUCCESS || r3 != KEM_SUCCESS){
             printf("operation failed");
             return 1;
    }

    if(memcmp(ss1, ss2, kem_ss_len(k)) == 0){
        printf("ROUNDTRIP OK: shared secrets do in fact match :)");
    } else{
        printf("ROUNDTRIP FAILED: The secrets do not in fact match :(");
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