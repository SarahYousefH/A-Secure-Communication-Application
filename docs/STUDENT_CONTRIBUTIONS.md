# Student Contributions

**ENCS4320 – Applied Cryptography | Birzeit University | Term 1252**

The project is divided into two independent stacks. Each student owns their files end-to-end — from reading the RFC, to writing the implementation, to writing the tests, to passing the test vectors.

---

## Student 1 — Key Establishment Stack

### What this stack does

Student 1 builds everything needed to establish a shared secret between the client and server and derive session keys from it. This happens once per session during the handshake (Phase A).

### Files owned

| File | RFC | What it does |
|------|-----|--------------|
| `primitives/sha256.py` | FIPS 180-4 | Hashes arbitrary bytes to a fixed 32-byte digest. Everything else depends on this. |
| `primitives/hmac_impl.py` | RFC 2104 | Computes a keyed MAC using SHA-256. Used to authenticate both sides during the handshake. |
| `primitives/hkdf.py` | RFC 5869 | Derives cryptographically strong session keys from the raw Diffie-Hellman output. |
| `primitives/x25519.py` | RFC 7748 | Performs elliptic-curve Diffie-Hellman key exchange. Both sides compute the same shared secret without ever sending it over the wire. |
| `protocol/handshake.py` | — | Orchestrates Phase A: exchanges X25519 public keys, computes the shared secret, runs mutual HMAC authentication, and calls HKDF to produce `key_c2s`, `key_s2c`, and `nonce_material`. |
| `server.py` | — | **Already implemented.** Thin entry point — no changes needed. |
| `tests/sha256/` | — | Test file + vectors for SHA-256 |
| `tests/hmac/` | — | Test file + vectors for HMAC |
| `tests/hkdf/` | — | Test file + vectors for HKDF |
| `tests/x25519/` | — | Test file + vectors for X25519 |

### Implementation order

Student 1 must implement in this order because each primitive depends on the one above:

```
sha256.py  →  hmac_impl.py  →  hkdf.py
x25519.py  (independent, can go in parallel)
handshake.py  (last — uses all four above)
```

### What the handshake does step by step

```
1. Generate ephemeral X25519 keypair
2. Exchange public keys with the peer over TCP
3. Compute shared_secret = X25519(my_private, peer_public)
4. Build transcript = public_c || public_s || "client" || "server" || "v1"
5. Compute auth_tag = HMAC(PSK, transcript) and send it
6. Receive peer's auth_tag and verify it — abort if wrong
7. Derive keys: key_c2s, key_s2c, nonce_material = HKDF(shared_secret, PSK, "SecureChannel-v1")
8. Return (key_c2s, key_s2c, nonce_material) to the caller
```

---

## Student 2 — Encryption Stack

### What this stack does

Student 2 builds everything needed to encrypt and authenticate messages after the handshake. This runs continuously during the messaging loop (Phase B).

### Files owned

| File | RFC | What it does |
|------|-----|--------------|
| `primitives/chacha20.py` | RFC 8439 | Stream cipher. Takes a key, nonce, and counter and produces a keystream that is XOR'd with the plaintext to produce ciphertext. |
| `primitives/poly1305.py` | RFC 8439 | Message authentication code. Given a one-time key and a message, produces a 16-byte tag. Any modification to the message changes the tag. |
| `primitives/aead.py` | RFC 8439 §2.8 | Combines ChaCha20 and Poly1305 into an AEAD construction. Encrypts the message body and authenticates both the ciphertext and the header. The header is passed as AAD (Additional Authenticated Data) — meaning it is protected by the tag but not encrypted, so it stays readable in plaintext. |
| `protocol/channel.py` | — | Orchestrates Phase B: runs the concurrent send/receive loop, builds headers, computes nonces, calls AEAD encrypt/decrypt, and handles replay detection via `last_seen_seq_number` inside `_recv_loop`. |
| `client.py` | — | **Already implemented.** Thin entry point — no changes needed. |
| `tests/chacha20/` | — | Test file + vectors for ChaCha20 |
| `tests/poly1305/` | — | Test file + vectors for Poly1305 |
| `tests/aead/` | — | Test file + vectors for AEAD |

### What is AEAD, and why is it split across two files?

**AEAD (Authenticated Encryption with Associated Data)** is a real standard algorithm defined in RFC 8439 §2.8. The spec for this project explicitly requires it:

> *"All application messages are protected with ChaCha20-Poly1305 (RFC 8439)."*

AEAD is a construction that combines two primitives:
- **ChaCha20** — encrypts the message (confidentiality)
- **Poly1305** — produces a tag over the ciphertext and any associated data (integrity)

Together they give you encryption + authentication in one operation. That combined operation is what `aead.py` implements.

The split between `aead.py` and `channel.py` follows a natural boundary:

| | `aead.py` | `channel.py` |
|---|---|---|
| What it is | Pure crypto primitive (RFC 8439) | Application protocol layer |
| What it knows | bytes in → bytes out | Messages, headers, sequence numbers, sockets |
| What it does | `encrypt(key, nonce, plaintext, aad)` → `(ciphertext, tag)` | Decides *what* to encrypt, builds the header, computes the nonce, calls `aead.py`, sends/receives over TCP |



### Implementation order

ChaCha20 and Poly1305 are independent — either can go first. AEAD combines both.

```
chacha20.py  ─┐
              ├──►  aead.py  →  channel.py  (last)
poly1305.py  ─┘

last_seen_seq_number  (plain integer inside _recv_loop)
```

### How the channel uses threads

The channel needs to do two things at the same time:
- Wait for the user to type something (blocks until they press Enter)
- Wait for a message to arrive from the other side (blocks until data comes in)

If you ran these one after the other, you would miss incoming messages while waiting for the user to type. Threading solves this: each direction gets its own thread so both run simultaneously.

```
run() launches two threads:

  Thread 1 — _send_loop        Thread 2 — _recv_loop
  ─────────────────────         ──────────────────────
  wait for user to type    │    wait for data on socket
  encrypt the message      │    decrypt the message
  send over socket         │    print to stdout
  repeat                   │    repeat
```

`run()` itself creates the two threads, starts them, and waits for both to finish (`.join()`). Student 2 only needs to implement `_send_loop` and `_recv_loop` as normal functions. No threading knowledge is needed inside them.

### What the channel does step by step

**`_send_loop` — one iteration:**
```
1. Read a line from stdin (blocks here until user types)
2. Increment outbound sequence number (seq)
3. Build header = { version, message_type, sender_id, seq }
4. Compute nonce = nonce_material XOR seq (12 bytes, little-endian)
5. ciphertext, tag = AEAD_encrypt(key_send, nonce, plaintext, aad=header)
6. Send: [header bytes][ciphertext][tag] over TCP
```

**`_recv_loop` — one iteration:**
```
1. Read bytes from socket (blocks here until data arrives)
2. Parse header
3. if seq <= last_seen_seq_number: reject  else: last_seen_seq_number = seq
4. Compute nonce = nonce_material XOR seq
5. plaintext = AEAD_decrypt(key_recv, nonce, ciphertext, tag, aad=header)
   → raise ValueError if tag does not match (tampered message)
6. Print plaintext to stdout
```

### Replay detection

Inside `_recv_loop` there is a plain integer variable `last_seen_seq_number = 0`. Every incoming message must have a sequence number strictly greater than this — if not, it is a replayed (or duplicate) message and gets rejected. After a valid message, `last_seen_seq_number` is updated. 
---


## Integration Point

The only place the two stacks meet is `server.py` and `client.py`:

```python
# After Student 1's handshake completes:
key_c2s, key_s2c, nonce_material = perform_handshake(sock, psk, identity)

# Student 2's channel receives the keys:
channel.run(sock, key_send=..., key_recv=..., nonce_material=nonce_material, identity=identity)
```

