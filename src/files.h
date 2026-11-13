#ifndef FILES_H
#define FILES_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
kem_status_t file_write(const char *path, const uint8_t *buf, size_t len);
kem_status_t file_read(const char *path, uint8_t *buf, size_t cap, size_t *len_out);
#endif
