#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
typedef struct{
     wc_Sha256 sha;
} transcript_t;
kem_status_t transcript_init(transcript_t *t);
kem_status_t transcript_append(transcript_t *t, const uint8_t *msg, size_t msg_len);
kem_status_t transcript_get_hash(transcript_t *t, uint8_t *out);
void transcript_free(transcript_t *t);
#endif
