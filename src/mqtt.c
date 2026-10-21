#include "mqtt.h"

kem_status_t mqtt_encode_remaining_length(size_t len, uint8_t *out, size_t out_cap, size_t *written){
  if(out == NULL || written == NULL || len > MQTT_MAX_REMAINING_LENGTH) return KEM_ERROR;
  size_t pos = 0;
  do{
    uint8_t byte = len % 128;
    len = len / 128;
    if(len > 0) byte = byte|0x80;
    if(pos < out_cap) out[pos] = byte;
    else return KEM_ERROR;
    pos++;
  }while(len > 0);
  *written = pos;
  return KEM_SUCCESS;
}
