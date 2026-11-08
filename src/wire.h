#ifndef WIRE_H
#define WIRE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"

typedef enum{
     WIRE_CLIENT_HELLO = 1,
     WIRE_SERVER_HELLO = 2,
     WIRE_SERVER_AUTH = 3,
     WIRE_CLIENT_AUTH = 4,
     WIRE_FINISHED = 5,
     WIRE_ENCRYPTED_EXTENSIONS = 6
} wire_msg_type_t;

typedef struct{
     size_t bytes_by_type[256];
     size_t total_bytes;
} wire_stats_t;

void wire_stats_init(wire_stats_t *stats);
kem_status_t wire_write(uint8_t type, const uint8_t *content, size_t content_len, uint8_t *out, size_t out_cap, size_t *written, wire_stats_t *stats);
kem_status_t wire_read(const uint8_t *in, size_t in_len, uint8_t *type_out, const uint8_t **content_out, size_t *content_len_out, size_t *consumed);
#endif