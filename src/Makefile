CC = gcc
CFLAGS = -Wall -O2 -I. -I$(HOME)/thesis/vendor/install/include
LDFLAGS = -L$(HOME)/thesis/vendor/install/lib
LIBS = -lwolfssl -loqs

CORE = kem.c kem_oqs.c kem_x25519.c kem_hybrid.c transcript.c keyschedule.c wire.c metrics.c credential.c transport.c handshake.c record.c channel.c

all: test_kem test_ks test_wire test_transport test_handshake test_baseline test_mqtt mqtt_smoke test_record

test_kem: test_kem.c kem.c kem_oqs.c kem_x25519.c kem_hybrid.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_ks: test_ks.c keyschedule.c transcript.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_record: test_record.c record.c keyschedule.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_wire: test_wire.c wire.c
	$(CC) $(CFLAGS) $^ -o $@

test_transport: test_transport.c transport.c
	$(CC) $(CFLAGS) $^ -o $@

test_handshake: test_handshake.c $(CORE)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) $(LIBS)

test_baseline: test_baseline.c baseline.c transport.c wire.c metrics.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS) -lwolfssl -lm

test_mqtt: test_mqtt.c mqtt.c
	$(CC) $(CFLAGS) $^ -o $@

mqtt_smoke: mqtt_smoke.c mqtt.c transport.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f test_kem test_ks test_wire test_transport test_handshake test_baseline test_mqtt mqtt_smoke *.o test_record

.PHONY: all clean
