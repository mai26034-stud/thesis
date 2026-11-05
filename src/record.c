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
