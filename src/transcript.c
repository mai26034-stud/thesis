#include "transcript.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <string.h>

void transcript_init(transcript_t *t){
     if(t == NULL) return;
     t->len = 0;
     return;
}

kem_status_t transcript_append(transcript_t *t, const uint8_t *msg, size_t msg_len){
     if(t == NULL) return KEM_ERROR;
     if(t->len + msg->len > sizeof(t->buffer)) return KEM_ERROR;
     memcpy(t->buffer + t->len, msg, msg_len);
     t->len += msg_len;
     return KEM_SUCCESS;
}
