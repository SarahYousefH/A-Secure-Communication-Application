# Phase A — Handshake

Key exchange and mutual authentication. Runs once at session start.

```
CLIENT                                        SERVER
──────                                        ──────

1. Generate ephemeral X25519 keypair          1. Generate ephemeral X25519 keypair
   (private_c, public_c)                         (private_s, public_s)

2. Send public_c               ─────────────────────────────────►

                               ◄─────────────────────────────────  2. Send public_s

3. Compute shared secret:                     3. Compute shared secret:
   X25519(private_c, public_s)                   X25519(private_s, public_c)
   → same result on both sides ✓                 → same result on both sides ✓

4. Build handshake transcript:                4. Build handshake transcript:
   public_c ‖ public_s ‖                         public_c ‖ public_s ‖
   "client" ‖ "server" ‖ "v1"                    "client" ‖ "server" ‖ "v1"

5. Compute auth tag:                          5. Compute auth tag:
   tag_c = HMAC(PSK, transcript)                 tag_s = HMAC(PSK, transcript)

6. Send tag_c                  ─────────────────────────────────►
                                                  Verify tag_c == expected?
                                                  → NO  : abort ✗
                                                  → YES : continue ✓

                               ◄─────────────────────────────────  6. Send tag_s
   Verify tag_s == expected?
   → NO  : abort ✗
   → YES : continue ✓

7. Both sides derive session keys:
   key_c2s, key_s2c, nonce_material = HKDF(
       input  = shared_secret,
       salt   = PSK,
       info   = b"SecureChannel-v1"
   )

══════════════════════ HANDSHAKE COMPLETE ══════════════════════
```

## Why Each Step Is Necessary

- **X25519** — establishes a shared secret without sending it over the network
- **HMAC authentication** — prevents man-in-the-middle: the attacker cannot forge a valid tag without the PSK
- **Both sides send a tag** — mutual authentication; client proves it knows PSK, server proves it knows PSK
- **HKDF** — raw X25519 output is not safe to use as a key; HKDF extracts and expands it into properly distributed keys
- **Two directional keys** — using one key in both directions enables reflection attacks
