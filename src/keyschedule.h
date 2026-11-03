#ifndef KEYSCHEDULE_H
#define KEYSCHEDULE_H
#include <stdint.h>
#include <stddef.h>
#include "kem.h"
typedef struct{
    uint8_t hs[32];
    uint8_t ahs[32];
    uint8_t ms[32];
}ks_state_t;
kem_status_t derive_handshake_secrets(const uint8_t *ss_ephemeral, size_t ss_eph_len, const uint8_t *ss_auth, size_t ss_auth_len, uint8_t *main_secret_out);
kem_status_t ks_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *out);
kem_status_t ks_expand_label(const uint8_t *secret, const char *label, const uint8_t *ctx, size_t ctx_len, uint8_t *out, size_t out_len);
kem_status_t ks_derive_secret(const uint8_t *secret, const char *label, const uint8_t *th, uint8_t *out);
kem_status_t ks_traffic_keys(const uint8_t *traffic_secret, uint8_t *key, uint8_t *iv);
kem_status_t ks_stage_handshake(ks_state_t *st, const uint8_t *ss_eph, size_t ss_eph_len);
kem_status_t ks_stage_auth(ks_state_t *st, const uint8_t *ss_auth, size_t ss_auth_len);
void ks_state_clear(ks_state_t *st);
#endif
