# Post-Quantum and Hybrid KEM Authentication for TLS-Secured IoT Messaging

Prototype implementation for the MSc thesis *"Post-Quantum and Hybrid KEM Authentication for TLS-Secured IoT Messaging: A Prototype-Based Performance Evaluation on Raspberry Pi"*, MSc in Applied Informatics, University of Macedonia.

The prototype implements a KEM-based server authentication for TLS 1.3, following the AuthKEM design (draft-celi-wiggers-tls-authkem), and compares it with a classical, signature-based TLS 1.3 handshake. Both are integrated into an MQTT telemetry pipeline (publisher, gateway, Mosquitto broker), so that the cost of authentication is measured inside a complete IoT application.

## Compared configurations

| Configuration | Server authentication | Library |
|---|---|---|
| ML-KEM-768 | KEM (FIPS 203) | liboqs |
| HQC-3 | KEM | liboqs |
| X-Wing | Hybrid KEM, X25519 + ML-KEM-768 (Barbosa et al. 2024) | liboqs + wolfCrypt |
| Baseline | TLS 1.3, X25519 key exchange, ECDSA certificates | wolfSSL |

In the three AuthKEM configurations, the ephemeral key exchange is X25519, with only the authentication KEM changing. The server's long-term KEM public key is carried in a credential signed by a test CA (Certificate Authority).

## Handshake (AuthKEM, server-only authentication)

```
Client                                              Server
ClientHello (ephemeral pk)          ------->
                                    <-------    ServerHello (ephemeral ct)
                                    <-------    {EncryptedExtensions}
                                    <-------    {Certificate}
{KEMEncapsulation}                  ------->
{Finished}                          ------->
                                    <-------    {Finished}
[Application Data]                  <------>    [Application Data]
```

- Key schedule: Handshake Secret -> Authenticated Handshake Secret -> Main Secret, with traffic secrets derived at the transcript points defined in the draft.
- Finished keys are derived from the Main Secret.
- The client sends its first application data (the MQTT CONNECT) right after its own Finished, before the server's Finished, as the draft allows. This data is implicitly authenticated: only he holder of the server's KEM private key can decrypt it. Explicit server authentication completes when the server's Finished is verified.
- Record protection: TLS 1.3 record layer with AES-128-GCM (TLS_AES_128_GCM_SHA256), the same cipher suite pinned in the baseline.

## Measurement pipeline

```
publisher -- (AuthKEM or TLS 1.3, TCP 19500)--> gateway --(MQTT, 127.0.0.1:1883)--> Mosquitto
```

- The publisher (the IoT device) connects, runs the handshake and sends MQTT CONNECT as early application data. After CONNACK it sends a PUBLISH (QoS 1, SenML JSWON on topic `tele/D001/3303/0/5700`), waits for the PUBACK and sends DISCONNECT.
- The gateway terminates the protected channel and relays the MQTT packets to the local Mosquitto broker. It serves one connection at a time.
- Both sides write one CSV row per connection.

## Repository layout

```
src/
  kem.c, kem.h            common KEM interface
  kem_oqs.c               ML-KEM-768 and HQC-3 (liboqs)
  kem_x25519.c            X25519 as a KEM (wolfCrypt)
  kem_hybrid.c            X-Wing combiner
  transcript.c            handshake transcript hash
  keyschedule.c           HKDF-based key schedule, traffic keys, Finished
  record.c                TLS 1.3 record protection (AES-128-GCM)
  channel.c               record-protected send/receive over a socket
  wire.c                  message framing
  credential.c            CA-signed server credential
  handshake.c             AuthKEM client and server handshake
  transport.c             TCP transport
  metrics.c               timing and byte counters, CSV output
  baseline.c              classical TLS 1.3 baseline (wolfSSL)
  mqtt.c                  MQTT 3.1.1 packet encoding and parsing
  test_*.c                unit and integration tests
  mqtt_smoke.c            end-to-end check against a local Mosquitto broker
analysis/
  analyze.py              summary of statistics (median, mean, 95% CI, bytes)
certs/                    test certificates for the baseline
VERSIONS.md               exact versions of libraries, build commands, and the verification log
```

## Building

Dependencies (liboqs 0.16.0, wolfSSL 5.9.2) are built from source into "vendor/install", which is not part of this repository. The exact build commands and options are listed in [VERSIONS.md](VERSIONS.md).

```
cd src
make
cd ..
src/provision keys
```

`provision` writes the CA public key (`ca.pub`) and, for each AuthKEM configuration, the server credential (`<KEM>.cred`) and the KEM private key (`<KEM>.sk`).

## Tests

| TEST | What it checks |
|---|---|
| `./test_kem` | KEM round trips for all configurations; X25519 against RFC 7748 §6.1; X-Wing tamper test |
| `./test_ks` | Transcript hash; key schedule, traffic keys and Finished against RFC 8448 §3 |
| `./test_record` | Record protection against RFC 8448 §3 (seal and open); tampered record rejected |
| `./test_wire` | Message framing |
| `./test_transport` | TCP transport |
| `./test_mqtt` | MQTT packet encoding and parsing |
| `./mqtt_smoke` | CONNECT / PUBLISH / PUBACK / DISCONNECT against Mosquitto on localhost:1883 |
| `./test_handshake` | AuthKEM handshakes over loopback for all three configurations, with early data; prints CSV |
| `./test_BASELINe` | Classical TLS 1.3 handshakes over loopback; prints CSV |

Each test prints its result and exits with the number of failures (0 failures for success).

## Measurements

```
cd src
./test_handshake > results.csv
./test_baseline > baseline.csv
cd ../analysis
python3 analyze.py
```

Each configuration runs 3 warm-up handshakes followed by 30 measured ones. Per-phase timings (key generation, encapsulation/decapsulation, credential verification, key schedule, total) and bytes sent are recorded per role. Final measurements are taken on a Raspberry Pi; results from development machines are not used in the thesis.

## Running experiments

Requirements: Mosquitto listening on localhost:1883 (on the gateway machine), the programs built with `make`, and the keys created with `provision`.

```
./scripts/run_experiments.sh <label>
```

| Variable | Default | Meaning |
|---|---|---|
| `ROUNDS` | 10 | number of rounds |
|`WARMUP` | 2 | warm-up connections per configuration and round (excluded from analysis) |
| `PER_ROUND` | 10 | measured connections per configuration and round |
| `PORT` | 19500 | gateway port |
| `TIMEOUT` | 300 | time limit per program run (seconds) |
| `NETIF` | lo | network interface (recorded in meta.txt) |
| `NOED` | 0 | 1 adds the ablation configurations without early data |
| `GW_HOST` | empty | empty: everything runs locally; `user@host`: the gateway runs on that machine via ssh |

## Status

- Done: KEM layer, key schedule, record layer, AuthKEM handshake with encrypted flight and Finished messages, classical baseline, MQTT packet layer.
- In progress: MQTT over the protected channel, gateway and publisher, measurement harness on Raspberry Pi.

## Test certificates

The files in `certs/` (including private keys) were generated offline with the OpenSSL CLI for the baseline experiments only. They have no use outside of this prototype.
