# Environment
- liboqs: 0.16.0
- wolfSSL: v5.9.2-stable
- Mosquitto: 2.0.18 (Ubuntu 24.04 package), default config (localhost only)
- Compiler: gcc 13.3.0
- Build flags: -Wall -O2 (Makefile)
- Analysis: Python 3.12.3, pandas 2.1.4, numpy 1.26.4, scipy 1.11.4
- Development machine: Intel core i5-10400, Ubuntu 24.04 on WSL2

## KEM sizes (bytes)
- HQC-3 (KEM_hqc_3):    pk 4514, sk 4602, ct 8978, ss 32
- ML-KEM-768 (KEM_ml_kem_768): pk 1184, sk 2400, ct 1088, ss 32
- X-Wing (X25519 + ML-KEM-768): pk 1216, sk 2464, ct 1120, ss 32
- X25519 (as a KEM, ephemeral): pk 32, sk 64 (private || public), ct 32, ss 32

## Link line
- AuthKEM programs (test_kem, test_ks, test_record, test_handshake, provision, gateway, publisher): -lwolfssl -loqs -lm (in that order).
- Baseline programs (test_baseline, gateway_baseline, publisher_baseline): -lwolfssl -lm
- libm is needed because objects of the static wolfSSL library that are pulled in by the ECC code use pow() and log().
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
From vendor/wolfssl:
```
make distclean
./configure --prefix=$HOME/thesis/vendor/install \
  --enable-static --disable-shared \
  --enable-curve25519 --enable-ed25519 --enable-mlkem \
  --enable-sha3 --enable-hkdf --enable-aesgcm \
  --enable-chacha --enable-poly1305 \
  --enable-sp --enable-sp-asm --enable-aesni --enable-intelasm \
  CFLAGS=-DWOLFSSL_PUBLIC_MP
make && make install
```
Verified in the installed options.h: WOLFSSL_HAVE_SP_ECC, WOLFSSL_SP_X86_64_ASM, WOLFSSL_AESNI, USE_INTEL_SPEEDUP.

The baseline pins in code (baseline.c, both sides):
```
  wolfSSL_CTX_set_groups -> WOLFSSL_ECC_X25519
  wolfSSL_CTX_set_cipher_list -> "TLS13-AES128-GCM-SHA256"
```
## Implementation choice
- Rule: every primitive uses the most optimized implementation that its library provides for the target platform.
- liboqs: ML-KEM-768 uses the optimized x86_64 implementation (mlkem-native); HQC-3 uses the portable C implementation, as liboqs 0.16.0 provides no optimized variant.
- wolfSSL: ECDSA P-256 uses the single-precision implementation with x86_64 assembly (--enable-sp, --enable-sp-asm); AES-GCM uses AES-NI (--enable-aesni); X25519 uses the x86_64 assembly implementation (--enable-intelasm).
- The same rule applies on the Raspberry Pi with the corresponding ARM options; the Pi build is recorded separately.

## Side-channel settings
- wolfSSL enables X25519 blinding (WOLFSSL_CURVE25519_BLINDING) by default only for the C-only implementation (wolfcrypt/settings.h). With USE_INTEL_SPEEDUP (or WOLFSSL_ARMASM) the assembly implementation is used and blinding is not defined.
- kem_x25519.c therefore calls wc_curve25519_set_rng only under #ifdef WOLFSSL_CURVE25519_BLINDING, following the library's own configuration.

## Configuration decisions
- wolfSSL 5.9.2 was built with --enable-mlkem, and makes use of X25519MLKEM768 and TLS_AES_256_GCM_SHA384 by default. The classical baseline therefore pins, on both sides, the group X25519 and the cipher suite TLS_AES_128_GCM_SHA256 (which is the mandatory-to-implement suite of RFC 8446 §9.1, which is also used by the AuthKEM record layer). Verified at runtime: X25519/TLS13-AES128-GCM-SHA256.
- liboqs was built without OpenSSL: OQS_USE_OPENSSL, OQS_USE_SHA2_OPENSSL, OQS_USE_AES_OPENSSL, OQS_USE_SHA3_OPENSSL are undefined in oqsconfig.h, and all tests link without -lcrypto.
- wolfSSL was built without the --enable-keylog-export option, and thus, no key-log file I/O occurs inside the timed handshake.
- All reported measurements use the configuration recorded in this file.
- TCP_NODELAY is set on every connection (AuthKEM and baseline), so that Nagle's algorithm combined with delayed ACKs does not add latency to flights of consecutive messages.
- Server credential (AuthKEM): id_len(2) | identity | pk_len(2) | KEM public key | sig_len(2) | signature. The signature is ECDSA P-256 with SHA-256 (DER, at most 72 bytes) by a test CA, the same signature algorithm as the baseline certificates. The CA signature therefore remains classical in all configurations.
- Transcript hash: a running SHA-256 state, updated once per message. key_schedule_ns covers HKDF, HMAC and the transcript hash finalization. Hashing of each message is included only in total_ns.

## Specification conformance
- AuthKEM handshake: draft-celi-wiggers-tls-authkem-06. Revision -07 (May of 2026) is a version bump only, according to its changelog, with the implication being that the implementation applies to both.
- X-Wing: construction of Barbosa et al. 2024 (IACR CiC 1(1), Definition 8), as cited in the thesis declaration. The label is first, and the KeyGen is seedless. Later IETF X-Wing drafts (from version -05 and onwards) do place the label last and derive the keys from a seed. These variants were not used in this thesis.
- ML-KEM-768: FIPS 203 (liboqs docs/algorithms/kem/ml_kem.yml, spec-version: ML-KEM; upstream: mlkem-native).
- HQC-3: HQC specification version 2025-08-22 (liboqs docs/algorithms/kem/hqc.yml, spec-version).

## Validation against published test vectors
- X25519: RFC 7748 §6.1, both directions (test_kem); shared secret in the RFC 7748 little-endian encoding.
- Key schedule (HKDF-Extract, Derive-Secret, traffic keys, finished key): RFC 8448 §3 (test_ks).
- Finished verify_data (HMAC-SHA256): RFC 8448 §3, client Finished (test_ks).
- Record layer (AES-128-GCM, nonce construction, AAD, padding removal): RFC 8448 §3, client Finished record, seal and open; a tampered record was rejected (test_record).

## KEM implementations (liboqs 0.16.0, default build, OQS_DIST_BUILD)
- ML-KEM-768: optimized x86_64 implementation enabled (OQS_ENABLE_KEM_ml_kem_768_x86_64).
- HQC-3: portable C implementation only; liboqs 0.16.0 provides no optimized variant.
- liboqs speed_kem on the development machine: HQC-3 keygen 5.0 ms, encaps 10.2 ms, decaps 15.1 ms; ML-KEM-768 keygen 10.9 μs, encaps 11.1 μs, decaps 13.8 μs.
- The Raspberry Pi build is recorded separately.

## Experiment Harness

## Memory checks (Valgrind)

## Raspberry Pi
