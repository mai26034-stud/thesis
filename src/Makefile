CC = gcc
CFLAGS = -Wall -02 -I. -I$(HOME)/thesis/vendor/install/include
LDFLAGS = -L$(HOME)/thesis/vendor/install/lib
LIBS = -lwolfssl -loqs -lcrypto

CORE = kem.c kem+oqs.c kemx25519.c kem_hybrid.c transcript.c keyschedule.c wire.c metrics.c credential.c transport.c handshake.c

all: test_kem test_ks test_wire test_transport test_handshake test_baseline

test_kem: test_kem.c kem.c kem_oqs.c kem_x25519.c kem_hybrid.c
  $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_ks: test_ks.c keyschedule.c transcript.c
  $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_wire: test_wire.c wire.c
  $(CC) $(CFLAGS) $^ -o $@

test_transport: test_transport.c transport.c
  $(CC) $(CFLAGS) $^ -o $@

test_handshake: test_handshake.c $(CORE)
  $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_baseline: test_baseline.c baseline.c transport.c wire.c metrics.c
  $(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lwolfssl -lcrypto

clean:
  rm -f test_kem test_ks test_wire test_transport test_handshake test_baseline *.o

.PHONY: all clean
