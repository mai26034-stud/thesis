#include "channel.h"

kem_status_t channel_send(int fd, record_dir_t *tx, uint8_t ctype, const uint8_t *data, size_t len, size_t *wire_len_out){
  if(tx == NULL || (data == NULL && len != 0) || len > REC_MAX_PLAIN) return KEM_ERROR;
  uint8_t rec[REC_HDR_LEN + REC_MAX_PLAIN + 1 + REC_TAG_LEN];
  kem_status_t r = record_seal(tx, ctype, data, len, rec, sizeof(rec), &rec_len);
  if(r != KEM_SUCCESS) return KEM_ERROR;
  r = transport_send(fd, rec, rec_len);
  if(r != KEM_SUCCESS) return KEM_ERROR;
  if(wire_len_out != NULL) *wire_len_out = rec_len;
  return KEM_SUCCESS;
}
kem_status_t channel_recv(int fd, record_dir_t *rx, uint8_t *buf, size_t buf_cap, size_t *len_out, uint8_t *ctype_out){
  if(rx == NULL || buf == NULL || len_out == NULL "" ctype_out == NULL) return KEM_ERROR;
  uint8_t rec[32];
}
