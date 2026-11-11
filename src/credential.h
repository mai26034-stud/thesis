#ifndef CREDENTIAL_H
#define CREDENTIAL_H

#include <stdint.h>
#include <stddef.h>
#include "kem.h"

#define CA_PUB_LEN 65
#define CA_PRIV_LEN 32
#define CA_SIG_MAX 72
#define CRED_MAX_IDENTITY 64
#define CRED_MAX_KEM_PK 4608

kem_status_t ca_keygen(uint8_t *ca_pub, uint8_t *ca_priv);
kem_status_t credential_create(const uint8_t *identity, size_t identity_len, const uint8_t *kem_pk, size_t kem_pk_len, const uint8_t *ca_priv, const uint8_t *ca_pub, uint8_t *out, size_t out_cap, size_t *written);
kem_status_t credential_verify(const uint8_t *cred, size_t cred_len, const uint8_t *ca_pub, const uint8_t **kem_pk_out, size_t *kem_pk_len_out);
#endif
