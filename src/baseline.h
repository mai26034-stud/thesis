#ifndef BASELINE_H
#define BASELINE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
#include "metrics.h"

kem_status_t baseline_client(int fd, const char *ca_cert_path, uint8_t *key_out, size_t *bytes_out, timings_t *tm);
kem_status_t baseline_server(int fd, const char *cert_path, const char *key_path, uint8_t *key_out, size_t *bytes_out, timings_t *tm);

#endif
