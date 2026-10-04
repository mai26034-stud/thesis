# Environment

liboqs: 0.16.0
wolfSSL: v5.9.2-stable

## KEM sizes (bytes)
HQC-3  (KEM_hqc_3):    pk 4514, sk 4602, ct 8978, ss 32
ML-KEM-768 (KEM_ml_kem_768): pk 1184, sk 2400, ct 1088, ss 32

## Link line
-lwolfssl -loqs -lcrypto (this order)
Include: -I vendor/install/include
Lib: -L vendor/install/lib

## liboqs build command (verified working)
cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
  -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;KEM_hqc_3" ..

## wolfSSL build command (verified working)
./configure --prefix=$HOME/thesis/vendor/install \
  --enable-static --disable-shared \
  --enable-curve25519 --enable-ed25519 --enable-mlkem \
  --enable-sha3 --enable-hkdf --enable-aesgcm \
  --enable-chacha --enable-poly1305 --enable-keylog-export \
  CFLAGS=-DWOLFSSL_PUBLIC_MP
