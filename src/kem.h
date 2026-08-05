#ifndef KEM_H
#define KEM_H
#include <stdint.h>
#include <stddef.h>
typedef enum{ 
    KEM_SUCCESS = 0, 
    KEM_NULL_ARGUMENT, 
    KEM_ERROR, KEM_UNKNOWN, 
    KEM_FAIL_MEM_ALLOC } kem_status_t;
typedef struct kem_t kem_t;
kem_t * kem_open(const char *);
void kem_close(kem_t *);
kem_status_t  kem_keypair(const kem_t *, uint8_t *, uint8_t*);
kem_status_t  kem_encaps(const kem_t *, const uint8_t *, uint8_t *, uint8_t *);
kem_status_t  kem_decaps(const kem_t *, const uint8_t *, const uint8_t *, uint8_t *);
size_t kem_pk_len(const kem_t *);
size_t kem_sk_len(const kem_t *);
size_t kem_ct_len(const kem_t *);
size_t kem_ss_len(const kem_t *);
#endif