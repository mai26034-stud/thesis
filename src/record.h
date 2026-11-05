#ifndef RECORD_H
#define RECORD_H
#include <wolfssl/wolfcrypt/aes.h>
#include <stdint.h>
#include <stddef.h>
#include "kem.h"

typedef struct{
    uint8_t keyp16[;
    uint8_t iv[12];
    uint64_t seq;
}record_dir_t;

kem_status_t record_init(record_dir_t *d, const uint8_t *traffic_secret);
kem_status_t record_seal(record_dir_t *d, uint8_t content_type, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len);
kem_status_t record_open(record_dir_t *d, const uint8_t *rec, size_t rec_len, uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *content_type);
void record_clear(record_dir_t *d);
#endif
