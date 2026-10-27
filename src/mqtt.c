#include "mqtt.h"
#include <string.h>

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

kem_status_t mqtt_build_connect(const char *client_id, uint16_t keepalive, uint8_t *buf, size_t cap, size_t *written){
  if(client_id == NULL || buf == NULL || written == NULL) return KEM_ERROR;
  size_t l = strlen(client_id);
  if(l < 1 || l > 23) return KEM_ERROR;
  size_t rem_len = 10 + l + 2;
  size_t rl_n;
  uint8_t t[4];
  kem_status_t ret = mqtt_encode_remaining_length(rem_len, t, sizeof(t), &rl_n);
  if(ret != KEM_SUCCESS) return KEM_ERROR; 
  size_t total = 1 + rl_n + rem_len;
  if(total > cap) return KEM_ERROR;
  size_t pos = 0;
  buf[pos++] = 0x10;
  memcpy(buf + pos, t, rl_n);
  pos += rl_n;
  buf[pos++] = 0x00;
  buf[pos++] = 0x04;
  buf[pos++] = 'M';
  buf[pos++] = 'Q';
  buf[pos++] = 'T';
  buf[pos++] = 'T';
  buf[pos++] = 0x04;
  buf[pos++] = 0x02;
  buf[pos++] = (uint8_t)(keepalive >> 8);
  buf[pos++] = (uint8_t)(keepalive & 0xFF);
  buf[pos++] = (uint8_t)(l >> 8);
  buf[pos++] = (uint8_t)(l & 0xFF);
  memcpy(buf + pos, client_id, l);
  pos += l;
  *written = pos;
  return KEM_SUCCESS;
}

kem_status_t mqtt_build_publish(const char *topic, const uint8_t *payload, size_t payload_len, uint8_t qos, uint16_t packet_id, uint8_t *buf, size_t cap, size_t *written){
  if(topic == NULL || buf == NULL || written == NULL) return KEM_ERROR;
  if(payload == NULL || payload_len > 0){
    printf("The length of the payload was regretably more than it should have been :(\n");
    return KEM_ERROR;
  }
  if(strlen(topic) < 1 || strlen(topic) > 65535) return KEM_ERROR;
  if(strchr(topic, '+') != NULL || strchr(topic, '#') != NULL) return KEM_ERROR;
  if(qos != 0 && qos != 1) return KEM_ERROR;
  if(qos == 1 && packet_id == 0) return KEM_ERROR;

  size_t rl_n;
  uint8_t t[4];
  kem_status_t ret = mqtt_encode_remaining_length(rem_len, t, sizeof(t), &rl_n);
  if(ret != KEM_SUCCESS) return KEM_ERROR; 
  size_t total = 1 + rl_n + rem_len;
  if(total > cap) return KEM_ERROR;
  size_t pos = 0;
  buf[pos++] = 0x10;
  memcpy(buf + pos, t, rl_n);
  pos += rl_n;
  buf[pos++] = 0x00;
  buf[pos++] = 0x04;
  buf[pos++] = 'M';
  buf[pos++] = 'Q';
  buf[pos++] = 'T';
  buf[pos++] = 'T';
  buf[pos++] = 0x04;
  buf[pos++] = 0x02;
  buf[pos++] = (uint8_t)(keepalive >> 8);
  buf[pos++] = (uint8_t)(keepalive & 0xFF);
  buf[pos++] = (uint8_t)(l >> 8);
  buf[pos++] = (uint8_t)(l & 0xFF);
  memcpy(buf + pos, client_id, l);
  pos += l;

  *written = pos;
  return KEM_SUCCESS;
}
