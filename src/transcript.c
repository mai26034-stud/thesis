#include "transcript.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <string.h>

void transcript_init(transcript_t *t){
     if(t == NULL) return KEM_ERROR;
     if(wc_InitSha256(&t->sha) != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t transcript_append(transcript_t *t, const uint8_t *msg, size_t msg_len){
     if(t == NULL || (msg == NULL && msg_len > 0)) return KEM_ERROR;
     if(wc_Sha256Update(&t->sha, msg, (word32)msg_len) != 0) return KEM_ERROR;
     memcpy(t->buffer + t->len, msg, msg_len);
     t->len += msg_len;
     return KEM_SUCCESS;
}

kem_status_t transcript_get_hash(const transcript_t *t, uint8_t *out){
     wc_Sha256 sha;
     if(t == NULL || out == NULL) return KEM_ERROR;
     int ret = wc_InitSha256(&sha);
     if(ret != 0) return KEM_ERROR;
     ret = wc_Sha256Update(&sha, t->buffer, (word32)t->len);
     if(ret != 0) return KEM_ERROR;
     ret = wc_Sha256Final(&sha, out);
     if(ret != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

void transcript_free(transcript_t *t){
     if(t != NULL) wc_Sha256Free(&t->sha);
     return;
}
