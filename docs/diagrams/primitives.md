# Primitive Dependency Graph

How the 7 primitives compose into the full protocol.

## Dependency Chain

```
FIPS 180-4          RFC 2104        RFC 5869
sha256.py  ───────► hmac_impl.py ──► hkdf.py
                                        │
RFC 7748                                ▼
x25519.py  ──────────────────────► handshake.py ──► SESSION KEYS
                                                      (key_c2s, key_s2c,
                                                       nonce_material)

RFC 8439                                              │
chacha20.py ─┐                                       ▼
             ├──► aead.py ──────────────────────► channel.py (replay detection inside)
poly1305.py ─┘
```

## What Each Primitive Does

| Primitive | RFC | Input → Output | Used By |
|-----------|-----|----------------|---------|
| SHA-256 | FIPS 180-4 | bytes → 32 bytes | HMAC |
| HMAC | RFC 2104 | (key, msg) → 32 bytes | HKDF, handshake auth |
| HKDF | RFC 5869 | (ikm, salt, info, len) → bytes | handshake (key derivation) |
| X25519 | RFC 7748 | (private, public) → 32 bytes | handshake (shared secret) |
| ChaCha20 | RFC 8439 | (key, nonce, counter, data) → bytes | AEAD |
| Poly1305 | RFC 8439 | (key, msg) → 16 bytes | AEAD |
| AEAD | RFC 8439 §2.8 | (key, nonce, pt, aad) → (ct, tag) | channel |
