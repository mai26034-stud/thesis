#ifndef MQTT_H
#define MQTT_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
#define MQTT_MAX_REMAINING_LENGTH 268435455

kem_status_t mqtt_encode_remaining_length(size_t len, uint8_t *out, size_t out_cap, size_t *written);
kem_status_t mqtt_build_connect(const char *client_id, uint16_t keepalive, uint8_t *buf, size_t cap, size_t *written);
kem_status_t mqtt_build_publish(const char *topic, const uint8_t *payload, size_t payload_len, uint8_t qos, uint16_t packet_id, uint8_t *buf, size_t cap, size_t *written);
kem_status_t mqtt_build_disconnect(uint8_t *buf, size_t cap, size_t *written);
kem_status_t mqtt_parse_connack(const uint8_t *buf, size_t len, uint8_t *return_code);
kem_status_t mqtt_parse_puback(const uint8_t *buf, size_t len, uint16_t *packet_id);
#endif
