#ifndef KEYSCHEDULE_H
#define KEYSCHEDULE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
kem_status_t derive_handshake_secrets(const uint8_t *ss_ephemeral, size_t ss_eph_len, const uint8_t *ss_auth, size_t ss_auth_len, uint8_t *main_secret_out);
#endif