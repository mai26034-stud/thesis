#include "transcript.h"
#include <string.h>

kem_status_t transcript_init(transcript_t *t){
     if(t == NULL) return KEM_ERROR;
     if(wc_InitSha256(&t->sha) != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t transcript_append(transcript_t *t, const uint8_t *msg, size_t msg_len){
     if(t == NULL || (msg == NULL && msg_len > 0)) return KEM_ERROR;
     if(wc_Sha256Update(&t->sha, msg, (word32)msg_len) != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

kem_status_t transcript_get_hash(transcript_t *t, uint8_t *out){
     if(t == NULL || out == NULL) return KEM_ERROR;
     if(wc_Sha256GetHash(&t->sha, out) != 0) return KEM_ERROR;
     return KEM_SUCCESS;
}

void transcript_free(transcript_t *t){
     if(t != NULL) wc_Sha256Free(&t->sha);
}
