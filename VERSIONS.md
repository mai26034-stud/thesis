# Environment
- liboqs: 0.16.0
- wolfSSL: v5.9.2-stable
- Mosquitto: 2.0.18 (Ubuntu 24.04 package), default config (localhost only)
- Compiler: gcc 13.3.0
- Build flags: -Wall -O2 (Makefile)

## KEM sizes (bytes)
- HQC-3  (KEM_hqc_3):    pk 4514, sk 4602, ct 8978, ss 32
- ML-KEM-768 (KEM_ml_kem_768): pk 1184, sk 2400, ct 1088, ss 32

## Link line
- AuthKEM tests (test_kem, test_ks, test_handshake): -lwolfssl -loqs (this order)
- Baseline (test_baseline): -lwolfssl -lm
- Include: -I vendor/install/include
- Lib: -L vendor/install/lib
- No OpenSSL in any measured path. OpenSSL CLI used only offline to generate the baseline test certificates (certs/).

## liboqs build command (verified working)
Static library (liboqs.a), built without OpenSSL.
From vendor/liboqs:
```
mkdir build-noossl && cd build-noossl
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=$HOME/thesis/vendor/install \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;KEM_hqc_3" \
  -DOQS_USE_OPENSSL=OFF ..
ninja && ninja install
```
Randomness: getentropy() of the OS (no OpenSSL RNG).

## wolfSSL build command (verified working)
```
./configure --prefix=$HOME/thesis/vendor/install \
  --enable-static --disable-shared \
  --enable-curve25519 --enable-ed25519 --enable-mlkem \
  --enable-sha3 --enable-hkdf --enable-aesgcm \
  --enable-chacha --enable-poly1305 \
  CFLAGS=-DWOLFSSL_PUBLIC_MP
```
The baseline pins in code (baseline.c, both sides):
```
  wolfSSL_CTX_set_groups -> WOLFSSL_ECC_X25519
  wolfSSL_CTX_set_cipher_list -> "TLS13-AES128-GCM-SHA256"
```
## Configuration decisions
- wolfSSL 5.9.2 was built with --enable-mlkem, and makes use of X25519MLKEM768 and TLS_AES_256_GCM_SHA384 by default. The classical baseline therefore pins, on both sides, the group X25519 and the cipher suite TLS_AES_128_GCM_SHA256 (which is the mandatory-to-implement suite of RFC 8446 §9.1, which is also used by the AuthKEM record layer). Verified at runtime: X25519/TLS13-AES128-GCM-SHA256.
- liboqs was built without OpenSSL: OQS_USE_OPENSSL, OQS_USE_SHA2_OPENSSL, OQS_USE_AES_OPENSSL, OQS_USE_SHA3_OPENSSL are undefined in oqsconfig.h, and all tests link without -lcrypto.
- wolfSSL was built without the --enable-keylog-export option, and thus, no key-log file I/O occurs inside the timed handshake.
- All reported measurements use the configuration recorded in this file.

## Specification conformance
- AuthKEM handshake: draft-celi-wiggers-tls-authkem-06. Revision -07 (May of 2026) is a version bump only, according to its changelog, with the implication being that the implementation applies to both.
- X-Wing: construction of Barbosa et al. 2024 (IACR CiC 1(1), Definition 8), as cited in the thesis declaration. The label is first, and the KeyGen is seedless. Later IETF X-Wing drafts (from version -05 and onwards) do place the label last and derive the keys from a seed. These variants were not used in this thesis.

## Validation against published test vectors
- X25519: RFC 7748 §6.1, both directions (test_kem); shared secret in the RFC 7748 little-endian encoding.
- Key schedule (HKDF-Extract, Derive-Secret, traffic keys, finished key): RFC 8448 §3 (test_ks).
- Finished verify_data (HMAC-SHA256): RFC 8448 §3, client Finished (test_ks).
- Record layer (AES-128-GCM, nonce construction, AAD, padding removal): RFC 8448 §3, client Finished record, seal and open; a tampered record was rejected (test_record).
