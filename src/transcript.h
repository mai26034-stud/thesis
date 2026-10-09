#ifndef TRANSCRIPT_H
#define TRANSCRIPT_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
typedef struct{
     uint8_t buffer[32768];
     size_t len;
} transcript_t;
void transcript_init(transcript_t *t);
kem_status_t transcript_append(transcript_t *t, const uint8_t *msg, size_t msg_len);
kem_status_t transcript_get_hash(const transcript_t *t, uint8_t *out);
#endif
