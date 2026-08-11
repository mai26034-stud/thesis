#include "kem.h"
#include "kem_internal.h"
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    WC_RNG rng;
} x25519_ctx_t;