#include "kem.h"
#include "kem_internal.h"
#include <string.h>

kem_t *kem_oqs_open(const char *name);

typedef kem_t *(*kem_opener_fn)(const char*);
typedef struct {
         const char *name;
         kem_opener_fn opener;
} kem_registry_entry_t;

static const kem_registry_entry_t registry[] = {
         { "ML-KEM-768", kem_oqs_open },
         { "HQC-3", kem_oqs_open}
};

kem_t *kem_open(const char *name){
         if(name == NULL) return NULL;
         size_t n = sizeof(registry)/sizeof(registry[0]);
         for(size_t i=0; i<n; i++){
                 if(strcmp(registry[i].name, name) == 0) return registry[i].opener(name);
         }
         return NULL;
}

void kem_close(kem_t *k){
         if(k == NULL) return;
         k->close(k);
}

kem_status_t kem_encaps(const kem_t *k, const uint8_t *pk, uint8_t *ct, uint8_t *ss){
         if(k == NULL) return KEM_NULL_ARGUMENT;
         return k->encaps(k, pk, ct, ss);
}
kem_status_t kem_decaps(const kem_t *k, const uint8_t *sk, const uint8_t *ct, uint8_t *ss){
         if(k == NULL) return KEM_NULL_ARGUMENT;
         return k->decaps(k, sk, ct, ss);
}
kem_status_t kem_keypair(const kem_t *k, uint8_t *pk, uint8_t *sk){
         if(k == NULL) return KEM_NULL_ARGUMENT;
         return k->keypair(k, pk, sk);
}

size_t kem_pk_len(const kem_t *k){
         if(k == NULL) return 0;
         return k->pk_len;
}
size_t kem_sk_len(const kem_t *k){
         if(k == NULL) return 0;
         return k->sk_len;
}
size_t kem_ct_len(const kem_t *k){
         if(k == NULL) return 0;
         return k->ct_len;
}
size_t kem_ss_len(const kem_t *k){
         if(k == NULL) return 0;
         return k->ss_len;
}