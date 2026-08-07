#include "kem.h"
#include "kem_internal.h"
#include "oqs/oqs.h"
#include <stdlib.h>
#include <string.h>

static kem_status_t translator_of_oqs_status(OQS_STATUS st){
    if(st == OQS_SUCCESS) return KEM_SUCCESS;
    else return KEM_ERROR;
}

static kem_status_t oqs_keypair(const kem_t *k, uint8_t *pk, uint8_t *sk){
         OQS_KEM *oqs = (OQS_KEM *)k->backend;
         return translator_of_oqs_status(OQS_KEM_keypair(oqs, pk, sk));
}

static kem_status_t oqs_encaps(const kem_t *k, const uint8_t *pk, uint8_t *ct, uint8_t *ss){
         OQS_KEM *oqs = (OQS_KEM *)k->backend;
         return translator_of_oqs_status(OQS_KEM_encaps(oqs, ct, ss, pk));
}

static kem_status_t oqs_decaps(const kem_t *k, const uint8_t *sk, const uint8_t *ct, uint8_t *ss){
         OQS_KEM *oqs = (OQS_KEM *)k->backend;
         return translator_of_oqs_status(OQS_KEM_decaps(oqs, ss, ct, sk));
}

kem_t * kem_oqs_open(const char *name){
         OQS_KEM * oqs = OQS_KEM_new(name);
         if(oqs == NULL) return NULL;

         kem_t *k = malloc(sizeof(kem_t));
         if(k == NULL) {
            OQS_KEM_free(oqs);
            return NULL;
         }
         
         k->name = oqs->method_name;
         k->nist_lvl = oqs->claimed_nist_level;
         k->sk_len = oqs->length_secret_key;
         k->ct_len = oqs->length_ciphertext;
         k->ss_len = oqs->length_shared_secret;
         k->pk_len = oqs->length_public_key;
         k->backend = oqs;
         k->keypair = oqs_keypair;
         k->encaps = oqs_encaps;
         k->decaps = oqs_decaps;
         return k;
}

void kem_oqs_close(kem_t *k){
    if(k == NULL) return;
    OQS_KEM * oqs = (OQS_KEM *)k->backend;
    OQS_KEM_free(oqs);
    free(k);
}
