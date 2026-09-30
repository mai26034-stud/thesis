#include "handshake.h"
#include "transport.h"
#include "transcript.h"
#include "keyschedule.h"
#include "kem_internal.h"
#include <string.h>
#include <stdlib.h>

kem_status_t handshake_client(int fd, const char *auth_kem_name, const uint8_t *ca_pub, uint8_t *main_secret_out, wire_stats_t *stats){}
kem_status_t handshake_server(int fd, const char *auth_kem_name, const uint8_t *cred, size_t cred_len, const uint8_t *auth_sk, uint8_t *main_secret_out, wire_stats_t *stats){}
