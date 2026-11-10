#ifndef CHANNEL_H
#define CHANNEL_H
#include "record.h"
#include "kem.h"

kem_status_t channel_send(int fd, record_dir_t *tx, uint8_t ctype, const uint8_t *data, size_t len, size_t *wire_len_out);
kem_status_t channel_recv(int fd, record_dir_t *rx, uint8_t *buf, size_t buf_cap, size_t *len_out, size_t *ctype_out);
#endif
