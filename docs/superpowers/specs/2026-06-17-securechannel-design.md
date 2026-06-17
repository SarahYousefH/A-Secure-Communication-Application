# SecureChannel — Project Design Spec
**Date:** 2026-06-17  
**Course:** ENCS4320 – Applied Cryptography, Birzeit University, Term 1252  
**Team:** Student 1, Student 2

---

## 1. Scope

Minimal viable implementation: the 7 required cryptographic primitives, the two-phase protocol (handshake + secure messaging), and the supporting infrastructure (server/client entry points, test suite, documentation). No bonus features.

---

## 2. File Structure

```
SecureChannel/
├── primitives/                  # All 7 crypto algorithms — student-written, no AI
│   ├── sha256.py                # Student 1
│   ├── hmac_impl.py             # Student 1
│   ├── hkdf.py                  # Student 1
│   ├── x25519.py                # Student 1
│   ├── chacha20.py              # Student 2
│   ├── poly1305.py              # Student 2
│   └── aead.py                  # Student 2
│
├── protocol/                    # Handshake + messaging logic — student-written, no AI
│   ├── handshake.py             # Student 1
│   ├── channel.py               # Student 2
│   └── replay.py                # Student 2
│
├── utilities/                   # Infrastructure boilerplate — AI-assisted allowed
│   └── channel_setup.py         # TCP socket creation, connection, teardown
│
├── tests/
│   ├── sha256/
│   │   ├── test_sha256.py       # Student 1
│   │   └── vectors.json         # Student 1 — from FIPS 180-4
│   ├── hmac/
│   │   ├── test_hmac.py         # Student 1
│   │   └── vectors.json         # Student 1 — from RFC 2104
│   ├── hkdf/
│   │   ├── test_hkdf.py         # Student 1
│   │   └── vectors.json         # Student 1 — from RFC 5869
│   ├── x25519/
│   │   ├── test_x25519.py       # Student 1
│   │   └── vectors.json         # Student 1 — from RFC 7748
│   ├── chacha20/
│   │   ├── test_chacha20.py     # Student 2
│   │   └── vectors.json         # Student 2 — from RFC 8439
│   ├── poly1305/
│   │   ├── test_poly1305.py     # Student 2
│   │   └── vectors.json         # Student 2 — from RFC 8439
│   ├── aead/
│   │   ├── test_aead.py         # Student 2
│   │   └── vectors.json         # Student 2 — from RFC 8439 §2.8
│   └── run_tests.py             # shared — imports and runs all 7 test modules
│
├── docs/
│   ├── diagrams/
│   │   ├── handshake.md         # Phase A visual: key exchange + auth flow
│   │   ├── messaging.md         # Phase B visual: encrypt/decrypt + replay flow
│   │   └── primitives.md        # Dependency graph: how the 7 primitives relate
│   ├── AI_USAGE.md              # shared — written honestly before submission
│   └── superpowers/
│       └── specs/
│           └── 2026-06-17-securechannel-design.md
│
├── server.py                    # Thin orchestrator: parse args → setup → handshake → channel
├── client.py                    # Thin orchestrator: parse args → setup → handshake → channel
├── config.json                  # shared — PSK and identity, do NOT commit real keys
├── requirements.txt             # shared — testing dependencies only (cryptography lib)
├── .gitignore                   # shared — includes .superpowers/ and config.json
└── README.md                    # shared
```

### server.py / client.py design philosophy

These files are intentionally thin — ~25 lines each. They do no crypto and no protocol logic. They only wire things together:

```python
# server.py (illustrative)
args   = cli.parse_args()
config = config.load("config.json")
sock   = channel_setup.listen(args.host, args.port)
keys   = handshake.perform_handshake(sock, config.psk, config.identity)
channel.run(sock, keys, identity=config.identity)
```

All logic lives in `protocol/` and `primitives/`. This makes the oral defense easier — you can point to exactly which file does what.

---

## 3. Team Split

### Student 1 — Key Establishment Stack

**Primitives (implement in this order — each depends on the one above):**
1. `primitives/sha256.py` — SHA-256 per FIPS 180-4
2. `primitives/hmac_impl.py` — HMAC per RFC 2104 (uses sha256)
3. `primitives/hkdf.py` — HKDF extract + expand per RFC 5869 (uses hmac)
4. `primitives/x25519.py` — X25519 key exchange per RFC 7748 (standalone)

**Protocol:**
- `protocol/handshake.py` — Phase A: key exchange + mutual authentication

**Entry point:**
- `server.py` — TCP server socket, CLI args, calls handshake then channel

**Tests:**
- `tests/sha256/`, `tests/hmac/`, `tests/hkdf/`, `tests/x25519/` — vectors from FIPS 180-4 / RFC 2104 / RFC 5869 / RFC 7748

---

### Student 2 — Encryption Stack

**Primitives (chacha20 and poly1305 are independent, aead combines them):**
1. `primitives/chacha20.py` — ChaCha20 stream cipher per RFC 8439
2. `primitives/poly1305.py` — Poly1305 MAC per RFC 8439
3. `primitives/aead.py` — ChaCha20-Poly1305 AEAD per RFC 8439 §2.8

**Protocol:**
- `protocol/replay.py` — sequence number tracking, strictly-increasing check
- `protocol/channel.py` — Phase B: encrypt/decrypt loop using AEAD + replay

**Entry point:**
- `client.py` — TCP client socket, CLI args, calls handshake then channel

**Tests:**
- `tests/chacha20/`, `tests/poly1305/`, `tests/aead/` — vectors from RFC 8439

---

## 4. Agreed Primitive Interfaces

These are the function signatures agreed on at setup. The bodies say `raise NotImplementedError`. Neither student changes another's signature after the first commit — only the body gets filled in.

### Student 1 — Primitives

```python
# primitives/sha256.py
def sha256(message: bytes) -> bytes:
    """Returns the 32-byte SHA-256 digest per FIPS 180-4."""
    raise NotImplementedError

# primitives/hmac_impl.py
def hmac(key: bytes, message: bytes) -> bytes:
    """Returns the 32-byte HMAC-SHA-256 tag per RFC 2104."""
    raise NotImplementedError

# primitives/hkdf.py
def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Returns `length` bytes of derived key material per RFC 5869."""
    raise NotImplementedError

# primitives/x25519.py
def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """Returns the 32-byte X25519 shared secret per RFC 7748."""
    raise NotImplementedError

def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key) — both 32 bytes."""
    raise NotImplementedError
```

### Student 2 — Primitives

```python
# primitives/chacha20.py
def chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Returns ChaCha20 keystream XOR'd with data per RFC 8439."""
    raise NotImplementedError

# primitives/poly1305.py
def poly1305(key: bytes, message: bytes) -> bytes:
    """Returns the 16-byte Poly1305 MAC per RFC 8439."""
    raise NotImplementedError

# primitives/aead.py
def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Returns (ciphertext, tag) per RFC 8439 §2.8."""
    raise NotImplementedError

def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """Returns plaintext, or raises ValueError if tag verification fails."""
    raise NotImplementedError
```

---

## 5. Integration Interface

The only point where Student 1's code meets Student 2's code. Agreed on at setup so both can work independently.

`protocol/handshake.py` exports one function:

```python
def perform_handshake(sock, psk: bytes, identity: str) -> tuple[bytes, bytes, bytes]:
    """
    Returns (key_c2s, key_s2c, nonce_material).
        key_c2s, key_s2c: 32 bytes each (ChaCha20 keys)
        nonce_material:   12 bytes (base nonce, XOR'd with sequence number)
    Raises RuntimeError on auth failure.
    """
```

`protocol/channel.py` receives this tuple from `server.py` / `client.py` and uses it directly. Neither student modifies the other's files after setup.

---

## 6. Protocol Summary

### Phase A — Handshake

1. Both sides generate ephemeral X25519 keypairs
2. Exchange public keys over TCP
3. Compute shared secret: `X25519(private, peer_public)`
4. Build transcript: `public_c ‖ public_s ‖ "client" ‖ "server" ‖ "v1"`
5. Each side computes `HMAC(PSK, transcript)` and sends their tag
6. Each side verifies the received tag — abort on failure
7. Both derive session keys: `HKDF(shared_secret, salt=PSK, info="SecureChannel-v1")` → `key_c2s, key_s2c, nonce_material`

### Phase B — Secure Messaging

Each message:
- Header (plaintext, authenticated): version, message_type, sender_id, sequence_number
- Nonce: `nonce_material XOR sequence_number`
- Body: `ChaCha20-Poly1305 encrypt(key, nonce, plaintext, aad=header)`
- Wire format: `[header][ciphertext][tag]`

On receive:
1. Parse header
2. Reject if `sequence_number <= last_seen` (replay protection)
3. Decrypt and verify tag — reject on failure
4. Display plaintext, update `last_seen`

---

## 6. Initial Setup (done together before split)

Tasks performed once, together, on `main`:

1. Create all directories and stub files (empty functions, correct signatures)
2. Write `config.json` template
3. Write `.gitignore`
4. Write `requirements.txt`
5. Write `tests/run_tests.py` skeleton (AI-assisted allowed)
6. Write `README.md`
7. Write `docs/AI_USAGE.md` skeleton (fill in honestly before submission)
8. First commit: `"Initial project scaffold"`

After this commit, each student works on their own files. The only shared file touched after setup is `README.md` (minor updates) and `AI_USAGE.md` (filled in at the end).

---

## 7. AI Usage Policy (per project spec Section 7)

### Allowed — AI assistance used in this project:
- `server.py` and `client.py` — socket handling and CLI argument parsing
- `utilities/channel_setup.py` — TCP socket boilerplate
- `tests/run_tests.py` — test runner scaffolding
- Initial file stubs and directory structure
- `README.md` draft (edited and owned by team)
- Debugging assistance and concept clarification during implementation

### Not allowed — written entirely by team without AI:
- All 7 primitive **implementations** in `primitives/` (function bodies)
- `protocol/handshake.py`
- `protocol/channel.py`
- `protocol/replay.py`
- All test vector files (`vectors.json`) — sourced directly from RFCs
- All test logic in `test_*.py` files
- Design report and conclusions (separate submission)

Note: `server.py` and `client.py` are thin orchestrators (~25 lines) that only call functions from `utilities/` and `protocol/`. Their structure is trivial and follows directly from the design.

Full details in `docs/AI_USAGE.md`.

---

## 8. Docs Plan

### README.md
- Project description and purpose
- How to run (server, client, tests)
- Algorithm table (7 primitives, file, RFC, role)
- Architecture diagrams (Phase A handshake flow, Phase B message flow)
- Security properties table (threat → defense)
- Team table (Student 1, Student 2, contributions)
- AI usage statement pointer → `docs/AI_USAGE.md`
- References (all RFCs/FIPS)

### docs/AI_USAGE.md
- What AI tools were used
- Specifically how they were used (with examples)
- Which parts were written entirely by the team
- Filled in honestly before final submission

---

## 9. Test Strategy

Each primitive is validated against official test vectors from its RFC/FIPS before being used in the protocol. A primitive that does not pass all official vectors is considered not implemented.

`run_tests.py` output format:
```
SHA-256      ... PASSED (2/2 vectors)
HMAC         ... PASSED (3/3 vectors)
HKDF         ... PASSED (2/2 vectors)
ChaCha20     ... PASSED (2/2 vectors)
Poly1305     ... PASSED (2/2 vectors)
AEAD         ... PASSED (2/2 vectors)
X25519       ... PASSED (2/2 vectors)

All tests passed ✓
```
