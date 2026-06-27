# A Secure Communication Application

**ENCS4320 – Applied Cryptography | Birzeit University | Term 1252**

---

## What Is This?

SecureChannel is a secure, end-to-end encrypted chat application built entirely from scratch in Python. Two parties — a **client** and a **server** — communicate over a TCP connection. The network between them is assumed to be hostile: an attacker can read, modify, or replay any packet. SecureChannel guarantees that despite this, all communication remains **confidential**, **authenticated**, and **tamper-proof**.

Every cryptographic primitive is implemented manually from its official RFC/FIPS specification — no external crypto libraries are used in the core implementation.

---

## How to Run

### 1. Install dependencies (for testing only)
```bash
pip install -r requirements.txt
```

### 2. Set up the pre-shared key (PSK)
```bash
cp psk_config.example.json psk_config.json
```
Edit `psk_config.json`:
```json
{ "psk": "your-strong-secret-agreed-out-of-band" }
```
Both sides use the same file — identity (client vs server) is determined by which script you run.

### 3. Start the server
```bash
python server.py --host 127.0.0.1 --port 5000
```

### 4. Start the client (in a separate terminal)
```bash
python client.py --host 127.0.0.1 --port 5000
```

### 5. Run the test suite
```bash
python tests/run_tests.py
```

Expected output (after all primitives are implemented):
```
SHA-256   ... PASSED (N/N vectors)
HMAC      ... PASSED (N/N vectors)
HKDF      ... PASSED (N/N vectors)
X25519    ... PASSED (N/N vectors)
ChaCha20  ... PASSED (N/N vectors)
Poly1305  ... PASSED (N/N vectors)
AEAD      ... PASSED (N/N vectors)

All tests passed ✓
```

---

## Algorithms Implemented

Every algorithm is implemented in pure Python from its official specification.

| Algorithm | File | Specification | Role |
|-----------|------|---------------|------|
| SHA-256 | `primitives/sha256.py` | FIPS 180-4 | Core hash — used by HMAC and HKDF |
| HMAC | `primitives/hmac_impl.py` | RFC 2104 | Handshake authentication |
| HKDF | `primitives/hkdf.py` | RFC 5869 | Key derivation from shared secret |
| X25519 | `primitives/x25519.py` | RFC 7748 | Elliptic-curve key exchange |
| ChaCha20 | `primitives/chacha20.py` | RFC 8439 | Stream cipher — encrypts messages |
| Poly1305 | `primitives/poly1305.py` | RFC 8439 | MAC — detects any tampering |
| ChaCha20-Poly1305 AEAD | `primitives/aead.py` | RFC 8439 §2.8 | Authenticated encryption |

---

## System Architecture

The session has two phases: **Handshake** (Phase A) then **Secure Messaging** (Phase B).

### Phase A — Handshake

```
CLIENT                                           SERVER
──────                                           ──────

generate keypair (private_c, public_c)           generate keypair (private_s, public_s)

send public_c          ──────────────────────►
                       ◄──────────────────────   send public_s

shared = X25519(private_c, public_s)             shared = X25519(private_s, public_c)
                                                 (same value on both sides)

transcript = public_c || public_s || "client" || "server" || "v1"

tag_c = HMAC(PSK, transcript)
send tag_c             ──────────────────────►   verify tag_c  →  abort if wrong

                       ◄──────────────────────   tag_s = HMAC(PSK, transcript)
verify tag_s  →  abort if wrong

key_c2s, key_s2c, nonce_material = HKDF(shared, salt=PSK, info="SecureChannel-v1")

══════════════════════ HANDSHAKE COMPLETE ══════════════════════
```

**Why each step matters:**
- `X25519` — neither side ever sends the shared secret over the wire
- `HMAC` tags — prove both sides know the PSK; stops man-in-the-middle attacks
- `HKDF` — raw Diffie-Hellman output is not safe to use directly as a key
- Two separate keys (`key_c2s`, `key_s2c`) — one key in both directions allows reflection attacks

### Phase B — Secure Messaging
```
Packet Format

+----------------------+----------------+----------------------+
| Header (16 bytes)    | Ciphertext     | Poly1305 Tag (16 B)  |
+----------------------+----------------+----------------------+

Header Layout

Byte(s)    Field
---------------------------------
1          Protocol Version
1          Message Type
1          Sender ID
1          Reserved
8          Sequence Number
4          Plaintext Length
---------------------------------
Total: 16 bytes
```
```
SENDER                                           RECEIVER
──────                                           ────────

build header:                                    read header (plaintext)
  protocol_version
  message_type
  sender_id
  reserved
  sequence_number
  plaintext_length
                                                 check seq_number > last_seen
nonce = nonce_material XOR seq_number               → reject if not (replay attack)

encrypt:                                         decrypt:
  ciphertext, tag =                                plaintext =
    ChaCha20_Poly1305(                               ChaCha20_Poly1305(
      key    = key_send,                               key    = key_recv,
      nonce  = nonce,                                  nonce  = nonce,
      plain  = message,                                cipher = ciphertext,
      aad    = header          ← authenticated         tag    = tag,
    )                            but not encrypted     aad    = header
                                                     )
                                                    → reject if tag invalid (tampered)
send: [header][ciphertext][tag]
                                                 display message
                                                 update last_seen = seq_number
```

**Why each step matters:**
- `ChaCha20` — encrypts; attacker cannot read the message
- `Poly1305` tag — any modification (even one bit) causes decryption failure
- `aad` = header — The entire protocol header (protocol version, message type,
          sender ID, reserved field, sequence number, and plaintext length) is
          authenticated but not encrypted. This allows the receiver to process the
          packet while ensuring any modification is detected during authentication. The           header is sent in plaintext so the receiver can read sender_id and seq_number           before decrypting, but it is included in the Poly1305 tag calculation so any            attacker modification is detected
- Sequence numbers — reject replayed messages the attacker captured and re-sent

### Primitive Dependency Chain

```
FIPS 180-4        RFC 2104          RFC 5869
sha256.py  ──►  hmac_impl.py  ──►  hkdf.py
                                       │
RFC 7748                               ▼
x25519.py  ────────────────────►  handshake.py  ──►  SESSION KEYS

RFC 8439                                              │
chacha20.py ─┐                                        ▼
             ├──►  aead.py  ───────────────────►  channel.py
poly1305.py ─┘
```

---

## File Structure

```
SecureChannel/
├── primitives/             # 7 crypto algorithms — each from its RFC
│   ├── sha256.py
│   ├── hmac_impl.py
│   ├── hkdf.py
│   ├── x25519.py
│   ├── chacha20.py
│   ├── poly1305.py
│   └── aead.py
├── protocol/
│   ├── handshake.py        # Phase A — key exchange + mutual authentication
│   └── channel.py          # Phase B — encrypt/decrypt loop + replay guard
├── utilities/
│   └── channel_setup.py    # TCP socket boilerplate
├── tests/
│   ├── sha256/             # test_sha256.py + vectors.json  (per primitive)
│   ├── hmac/
│   ├── hkdf/
│   ├── x25519/
│   ├── chacha20/
│   ├── poly1305/
│   ├── aead/
│   └── run_tests.py
├── docs/
│   ├── STUDENT_CONTRIBUTIONS.md
│   ├── AI_USAGE.md
│   └── diagrams/
├── server.py               # Thin entry point — calls handshake then channel
├── client.py               # Thin entry point — calls handshake then channel
├── psk_config.example.json # Config template — copy to psk_config.json locally
└── requirements.txt
```

---

## Security Properties

| Threat | Defense |
|--------|---------|
| Eavesdropping | ChaCha20 encryption |
| Message tampering | Poly1305 tag over ciphertext |
| Header tampering | Header is AEAD associated data |
| Man-in-the-middle | HMAC(PSK, transcript) — can't forge without PSK |
| Replay attack | Strictly increasing sequence numbers |
| Nonce reuse | Nonce = nonce_material XOR sequence_number |
| Weak session keys | HKDF extract + expand |

---

## AI Usage

See [`docs/AI_USAGE.md`](docs/AI_USAGE.md) for a full statement of what AI was used for and what the team wrote independently.

---

## Team

| Name            | ID      | Stack |
|-----------------|---------|-------|
| Sarah Hassouneh | 1210068 | Key establishment (SHA-256, HMAC, HKDF, X25519, handshake) |
| Islam Zayed     | 1230007 | Encryption (ChaCha20, Poly1305, AEAD, channel) |

See [`docs/STUDENT_CONTRIBUTIONS.md`](docs/STUDENT_CONTRIBUTIONS.md) for detailed breakdown.

---

## Quick Run of terminal commands

```bash
# Terminal 1
python server.py --host 127.0.0.1 --port 5000

# Terminal 2 (same psk_config.json)
python client.py --host 127.0.0.1 --port 5000
```

---
