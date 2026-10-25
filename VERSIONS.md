# Environment

liboqs: 0.16.0
wolfSSL: v5.9.2-stable
Compiler: gcc 13.3.0
Build flags: -Wall -O2 (Makefile)

## KEM sizes (bytes)
HQC-3  (KEM_hqc_3):    pk 4514, sk 4602, ct 8978, ss 32
ML-KEM-768 (KEM_ml_kem_768): pk 1184, sk 2400, ct 1088, ss 32

## Link line
AuthKEM tests (test_kem, test_ks, test_handshake): -lwolfssl -loqs (this order)
Baseline (test_baseline): -lwolfssl -lm
Include: -I vendor/install/include
Lib: -L vendor/install/lib
No OpenSSL in any measured path. OpenSSL CLI used only offline to generate the baseline test certificates (certs/).

## liboqs build command (verified working)
Static library (liboqs.a), built without OpenSSL.
From vendor/liboqs:
mkdir build-noossl && cd build-noossl
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$HOME/thesis/vendor/install \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;KEM_hqc_3" \
  -DOQS_USE_OPENSSL=OFF ..
ninja && ninja install
Randomness: getentropy() of the OS (no OpenSSL RNG).

## wolfSSL build command (verified working)
./configure --prefix=$HOME/thesis/vendor/install \
  --enable-static --disable-shared \
  --enable-curve25519 --enable-ed25519 --enable-mlkem \
  --enable-sha3 --enable-hkdf --enable-aesgcm \
  --enable-chacha --enable-poly1305 \
  CFLAGS=-DWOLFSSL_PUBLIC_MP
Note: with --enable-mlkem, TLS 1.3 negotiates X25519MLKEM768 by default.
The baseline therefore pins in code (baseline.c, both sides):
  wolfSSL_CTX_set_groups -> WOLFSSL_ECC_X25519
  wolfSSL_CTX_set_cipher_list -> "TLS13-AES128-GCM-SHA256"

## Verifications
- 2026-10-24, baseline before pinning: TLS13-AES256-GCM-SHA384 / X25519MLKEM768
- 2026-10-24, baseline after pinning: TLS13-AES128-GCM-SHA256 / X25519
- 2026-10-24, LIBOQS: OQS_USE_OPENSSL, OQS_USE_SHA2_OPENSSL, OQS_USE_AES_OPENSSL, OQS_USE_SHA3_OPENSSL all undef in oqsconfig.h. All tests pass without -lcrypto.
- Measurements taken before 2026-10-24 are invalid (baseline used X25519MLKEM768; liboqs used OpenSSL).
- 2026-10-25, wolfSSL rebuilt without --enable-keylog-export (key log file was written inside the timed handshake).Baseline median total: 1.42ms -> 1.20 ms.
