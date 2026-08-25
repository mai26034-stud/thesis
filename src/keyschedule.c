#include "kem.h"
#include "kem_internal.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <string.h>
#include <stdint.h>

static const char TLS13_PREFIX[6] = {'t', 'l', 's', '1', '3', ' '};
static kem_status_t hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *context, size_t context_len, uint8_t *out, size_t out_len){
  uint8_t hkdf_label[512];
  size_t pos = 0;

  hkdf_label[pos++] = (uint8_t)(out_len >> 8);
  hkdf_label[pos++] = (uint8_t)(out_len & 0xFF);

  size_t label_len = strlen(label);
  hkdf_label[pos++] = (uint8_t)(6 + label_len);

  memcpy(hkdf_label + pos, TLS13_PREFIX, 6);
  pos +=6;

  memcpy(hkdf_label + pos, label, label_len);
  pos += label_len;

  hkdf_label[pos++] = (uint8_t)context_len;
  if(context_len > 0){
       memcpy(hkdf_label + pos, context, context_len);
       pos += context_len;
  }

  int ret = wc_HKDF_Expand(WC_SHA256, secret, (word32)secret_len, hkdf_label, (word32)pos, out, (word32)out_len); //να το ξαναδώ και επίσης ότι το WC_SHA256 είναι το σωστό όνομα
  if(ret != 0) return KEM_ERROR;
  return KEM_SUCCESS;
}
