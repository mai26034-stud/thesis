#ifndef HANDSHAKE_H
#define HANDSHAKE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
#include "wire.h"
#include "credential.h"

#define HS_MAIN_SECRET_LEN 32
#define EPHEMERAL_KEM "X25519"

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats);
kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats);
#endif
