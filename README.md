# Post-Quantum and Hybrid KEM Authentication for TLS-Secured IoT Messaging

Prototype implementation for the MSc thesis *"Post-Quantum and Hybrid KEM Authentication for TLS-Secured IoT Messaging: A Prototype-Based Performance Evaluation on Raspberry Pi"*, MSc in Applied Informatics, University of Macedonia.

The prototype implements a KEM-based server authentication for TLS 1.3, following the AuthKEM design (draft-celi-wiggers-tls-authkem), and compares it with a classical, signature-based TLS 1.3 handshake. The target use case is MQTT telemetry from IoT devices.

## Compared configurations

| Configuration | Server authentication | Library |
|---|---|---|
| ML-KEM-768 | KEM (FIPS 203) | liboqs |
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
- Record protection: TLS 1.3 record layer with AES-128-GCM (TLS_AES_128_GCM_SHA256), the same cipher suite pinned in the baseline.

## Repository layout
