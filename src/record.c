#include "record.h"
#include "keyschedule.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <string.h>

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

static void build_nonce(const record_dir_t *d, uint8_t *nonce){
    memcpy(nonce, d->iv,12);
    for(int i = 0; i < 8; i++){
        nonce[4 + i] ^= (uint8_t)(d->seq >> (56 - 8*i));
    }
}

kem_status_t record_seal(record_dir_t *d, uint8_t content_type, const uint8_t *in, size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len){
    if(d == NULL || out == NULL || out_len == NULL) return KEM_ERROR;
    if(in_len != 0 && in == NULL) return KEM_ERROR;
    if(in_len > REC_MAX_PLAIN) return KEM_ERROR;
    if(d->seq == UINT64_MAX) return KEM_ERROR;
    size_t inner_len = in_len + 1;
    size_t ct_len = inner_len + REC_TAG_LEN;
    if(out_cap < REC_HDR_LEN + ct_len) return KEM_ERROR;
    uint8_t inner[REC_MAX_PLAIN + 1];
    if(in_len > 0) memcpy(inner, in, in_len);
    inner[in_len] = content_type;
    out[0] = 0x17;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = (uint8_t)(ct_len >> 8);
    out[4] = (uint8_t)(ct_len & 0xFF);
    uint8_t nonce[12];
    build_nonce(d, nonce);
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if(ret == 0) ret = wc_AesGcmSetKey(&aes, d->key, 16);
    if(ret == 0) ret = wc_AesGcmEncrypt(&aes, out + REC_HDR_LEN, inner, (word32)inner_len, nonce, 12, out + REC_HDR_LEN + inner_len, REC_TAG_LEN, out, REC_HDR_LEN);
    wc_AesFree(&aes);
    wc_ForceZero(&aes, sizeof(aes));
    wc_ForceZero(inner, inner_len);
    if(ret != 0) return KEM_ERROR;
    else{
        *out_len = REC_HDR_LEN + ct_len;
        d->seq++;
        return KEM_SUCCESS;
    }
}

void record_clear(record_dir_t *d){
    if(d == NULL) return;
    wc_ForceZero(d, sizeof(*d));
}

kem_status_t record_open(record_dir_t *d, const uint8_t *rec, size_t rec_len, uint8_t *out, size_t out_cap, size_t *out_len, uint8_t *content_type){
    if(d == NULL || rec == NULL || out == NULL || out_len == NULL || content_type == NULL) return KEM_ERROR;
    if(d->seq == UINT64_MAX) return KEM_ERROR;
    if(rec_len < REC_HDR_LEN + REC_TAG_LEN + 1) return KEM_ERROR;
    if(rec[0] != 0x17) return KEM_ERROR;
    size_t ct_len = ((size_t)rec[3] << 8) | rec[4];
    if(ct_len != rec_len - REC_HDR_LEN || ct_len > REC_MAX_PLAIN + 256) return KEM_ERROR;
    size_t inner_len = ct_len - REC_TAG_LEN;
    if(out_cap < inner_len) return KEM_ERROR;
    uint8_t nonce[12];
    build_nonce(d, nonce);
    Aes aes;
    int ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if(ret == 0) ret = wc_AesGcmSetKey(&aes, d->key, 16);
    if(ret == 0) ret = wc_AesGcmDecrypt(&aes, out, rec + REC_HDR_LEN, (word32)inner_len, nonce, 12, rec + REC_HDR_LEN + inner_len, REC_TAG_LEN, rec, REC_HDR_LEN);
    wc_AesFree(&aes);
    wc_ForceZero(&aes, sizeof(aes));
    if(ret != 0){
        wc_ForceZero(out, inner_len);
        return KEM_ERROR;
    }
    size_t i = inner_len;
    while(i > 0 && out[i - 1] == 0){
        i--;
    }
    if(i == 0){
        wc_ForceZero(out, inner_len);
        return KEM_ERROR;
    }
    size_t plain_len = i - 1;
    if(plain_len > REC_MAX_PLAIN){
        wc_ForceZero(out, inner_len);
        return KEM_ERROR;
    }
    *content_type = out[i - 1];
    *out_len = plain_len;
    d->seq++;
    return KEM_SUCCESS;
}