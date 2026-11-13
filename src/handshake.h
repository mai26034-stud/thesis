#ifndef HANDSHAKE_H
#define HANDSHAKE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
#include "wire.h"
#include "credential.h"
#include "metrics.h"
#include "record.h"

#define EPHEMERAL_KEM "X25519"

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, const uint8_t *early_data, size_t early_len, record_dir_t *app_tx, record_dir_t *app_rx, wire_stats_t *stats, timings_t *tm);
kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, record_dir_t *app_tx, record_dir_t *app_rx, wire_stats_t *stats, timings_t *tm);
#endif
