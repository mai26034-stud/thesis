#include "record.h"
#include "keyschedule.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <string.h>
#define REC_HDR_LEN 5
#define REC_TAG_LEN 16
#define REC_MAX_PLAIN 16384

kem_status_t record_init(record_dir_t *d, const uint8_t *traffic_secret){
    if(d == NULL || traffic_secret == NULL) return KEM_ERROR;    
    kem_status_t r = ks_traffic_keys(traffic_secret, d->key, d->iv);
    if(r != KEM_SUCCESS){
      record_clear(d);
      return KEM_ERROR;
    }
    d->seq = 0;
    return KEM_SUCCESS;
}

kem_status_t record_seal(record_dir_t *d, uint8_t content_type, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if(d == NULL || out == NULL || out_len == NULL) return KEM_ERROR;
    if(in_len != 0 && in == NULL) return KEM_ERROR;
    if(in_len > REC_MAX_PLAIN) return KEM_ERROR;
    if(d->seq == UINT64_MAX) return KEM_ERROR;
    inner_len = in_len + 1;
    ct_len = inner_len + REC_TAG_LEN;
    if(out_cap < REC_HDR_LEN) return KEM_ERROR;
}
