#ifndef KEM_INTERNAL_H
#define KEM_INTERNAL_H
#include "kem.h"
typedef kem_status_t (*kem_keypair_fn)(const kem_t *, uint8_t *, uint8_t *);
typedef kem_status_t (*kem_encaps_fn)(const kem_t *, const uint8_t *, uint8_t *, uint8_t *);
typedef kem_status_t (*kem_decaps_fn)(const kem_t *, const uint8_t *, const uint8_t *, uint8_t *);
typedef void (*kem_close_fn)(kem_t *);
typedef struct kem_t{
    const char * name;
    uint8_t nist_lvl;
    size_t pk_len;
    size_t sk_len;
    size_t ct_len;
    size_t ss_len;
    kem_keypair_fn keypair;
    kem_encaps_fn encaps;
    kem_decaps_fn decaps;
    kem_close_fn close;
    void *backend;
} kem_t;
#endif