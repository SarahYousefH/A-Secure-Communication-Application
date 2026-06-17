# SecureChannel — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Scaffold the complete SecureChannel project — all directories, stub files with agreed interfaces, test infrastructure, and documentation — so both students can immediately split and begin implementing their respective primitives from the RFCs.

**Architecture:** Two independent stacks (key establishment: SHA-256→HMAC→HKDF→X25519→handshake / encryption: ChaCha20+Poly1305→AEAD→channel) with a thin integration point at `perform_handshake()`. All crypto bodies start as `raise NotImplementedError`. All boilerplate (sockets, CLI, test runner) is written during scaffold.

**Tech Stack:** Python 3.11+, stdlib only for core (`socket`, `argparse`, `json`, `struct`, `os`), `cryptography` lib for test verification only.

---

## Phase 1 — Scaffold (Both Students Together)

### Task 1: Create Directory Structure

**Files:**
- Create all directories

- [ ] **Step 1: Create all project directories**

```bash
mkdir -p primitives protocol utilities tests/sha256 tests/hmac tests/hkdf tests/x25519 tests/chacha20 tests/poly1305 tests/aead docs/diagrams
```

- [ ] **Step 2: Create `__init__.py` files so Python treats folders as packages**

```bash
touch primitives/__init__.py protocol/__init__.py utilities/__init__.py
```

- [ ] **Step 3: Verify structure**

```bash
find . -not -path './.git/*' -not -path './.superpowers/*' | sort
```

Expected output should show all directories listed above.

- [ ] **Step 4: Commit**

```bash
git add .
git commit -m "chore: create project directory structure"
```

---

### Task 2: Write config.json Template and requirements.txt

**Files:**
- Create: `config.json.example`
- Create: `requirements.txt`

- [ ] **Step 1: Write `config.json.example`**

```json
{
  "psk": "replace-with-your-strong-secret-key-agreed-out-of-band",
  "identity": "server"
}
```

Note: `config.json` is in `.gitignore`. Each team member creates their own local `config.json` from this template.

- [ ] **Step 2: Write `requirements.txt`**

```
cryptography>=41.0.0
```

This is the only external dependency, used only in tests to verify our implementations produce correct output.

- [ ] **Step 3: Commit**

```bash
git add config.json.example requirements.txt
git commit -m "chore: add config template and requirements"
```

---

### Task 3: Stub — Student 1 Primitives

**Files:**
- Create: `primitives/sha256.py`
- Create: `primitives/hmac_impl.py`
- Create: `primitives/hkdf.py`
- Create: `primitives/x25519.py`

These are the agreed interfaces. Bodies are `raise NotImplementedError` — Student 1 fills them in.

- [ ] **Step 1: Write `primitives/sha256.py`**

```python
def sha256(message: bytes) -> bytes:
    """Returns the 32-byte SHA-256 digest of message per FIPS 180-4."""
    raise NotImplementedError
```

- [ ] **Step 2: Write `primitives/hmac_impl.py`**

```python
from primitives.sha256 import sha256

def hmac(key: bytes, message: bytes) -> bytes:
    """Returns the 32-byte HMAC-SHA-256 tag per RFC 2104."""
    raise NotImplementedError
```

- [ ] **Step 3: Write `primitives/hkdf.py`**

```python
from primitives.hmac_impl import hmac

def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Returns `length` bytes of derived key material per RFC 5869.
    
    Performs HKDF-Extract followed by HKDF-Expand.
    length must be <= 255 * 32 (HashLen for SHA-256).
    """
    raise NotImplementedError
```

- [ ] **Step 4: Write `primitives/x25519.py`**

```python
def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key) — both 32 bytes.
    
    private_key is 32 random bytes (clamped per RFC 7748 §5).
    public_key is the corresponding X25519 public key.
    """
    raise NotImplementedError

def x25519(private_key: bytes, public_key: bytes) -> bytes:
    """Returns the 32-byte X25519 shared secret per RFC 7748.
    
    Raises ValueError if the result is the all-zero point.
    """
    raise NotImplementedError
```

- [ ] **Step 5: Commit**

```bash
git add primitives/
git commit -m "chore: add Student 1 primitive stubs (sha256, hmac, hkdf, x25519)"
```

---

### Task 4: Stub — Student 2 Primitives

**Files:**
- Create: `primitives/chacha20.py`
- Create: `primitives/poly1305.py`
- Create: `primitives/aead.py`

- [ ] **Step 1: Write `primitives/chacha20.py`**

```python
def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Returns one 64-byte ChaCha20 keystream block per RFC 8439 §2.1.
    
    key: 32 bytes
    counter: 32-bit unsigned integer
    nonce: 12 bytes
    """
    raise NotImplementedError

def chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Returns ChaCha20 keystream XOR'd with data per RFC 8439 §2.4.
    
    key: 32 bytes
    nonce: 12 bytes
    counter: initial block counter (0 for AEAD, 1 for raw encryption)
    data: plaintext or ciphertext of any length
    """
    raise NotImplementedError
```

- [ ] **Step 2: Write `primitives/poly1305.py`**

```python
def poly1305(key: bytes, message: bytes) -> bytes:
    """Returns the 16-byte Poly1305 MAC per RFC 8439 §2.5.
    
    key: 32 bytes (r || s), where r is the first 16 bytes (clamped)
    message: arbitrary length bytes
    """
    raise NotImplementedError
```

- [ ] **Step 3: Write `primitives/aead.py`**

```python
from primitives.chacha20 import chacha20
from primitives.poly1305 import poly1305

def chacha20_poly1305_encrypt(
    key: bytes,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> tuple[bytes, bytes]:
    """Returns (ciphertext, tag) per RFC 8439 §2.8.
    
    key: 32 bytes
    nonce: 12 bytes
    plaintext: arbitrary length
    aad: additional authenticated data (authenticated but not encrypted)
    tag: 16-byte Poly1305 MAC
    """
    raise NotImplementedError

def chacha20_poly1305_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes:
    """Returns plaintext per RFC 8439 §2.8, or raises ValueError on auth failure.
    
    IMPORTANT: verify the tag BEFORE decrypting. Use constant-time comparison.
    Raises ValueError if tag does not match.
    """
    raise NotImplementedError
```

- [ ] **Step 4: Commit**

```bash
git add primitives/
git commit -m "chore: add Student 2 primitive stubs (chacha20, poly1305, aead)"
```

---

### Task 5: Stub — Protocol Layer

**Files:**
- Create: `protocol/handshake.py`
- Create: `protocol/replay.py`
- Create: `protocol/channel.py`

- [ ] **Step 1: Write `protocol/handshake.py`**

```python
import socket
from primitives.x25519 import generate_keypair, x25519
from primitives.hmac_impl import hmac
from primitives.hkdf import hkdf

def perform_handshake(sock: socket.socket, psk: bytes, identity: str) -> tuple[bytes, bytes, bytes]:
    """Performs the Phase A handshake and returns session keys.
    
    Executes: ephemeral key exchange (X25519) + mutual authentication (HMAC)
    + key derivation (HKDF).
    
    identity: "client" or "server" — determines send/receive order
    
    Returns: (key_c2s, key_s2c, nonce_material)
        key_c2s:        32 bytes — ChaCha20 key for client→server messages
        key_s2c:        32 bytes — ChaCha20 key for server→client messages
        nonce_material: 12 bytes — base nonce XOR'd with sequence number per message
    
    Raises RuntimeError if peer authentication fails.
    """
    raise NotImplementedError
```

- [ ] **Step 2: Write `protocol/replay.py`**

```python
class ReplayGuard:
    """Tracks sequence numbers to detect and reject replayed messages."""

    def __init__(self) -> None:
        """Initialises the guard. First valid sequence number is 1."""
        self._last_seen: int = 0

    def check_and_update(self, seq: int) -> None:
        """Accepts seq if seq > last_seen, then updates last_seen.
        
        Raises ValueError if seq <= last_seen (replay or out-of-order).
        """
        raise NotImplementedError
```

- [ ] **Step 3: Write `protocol/channel.py`**

```python
import socket
from primitives.aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from protocol.replay import ReplayGuard

def run(
    sock: socket.socket,
    key_send: bytes,
    key_recv: bytes,
    nonce_material: bytes,
    identity: str,
) -> None:
    """Runs the Phase B secure messaging loop until the connection closes.
    
    Reads input from stdin, encrypts with key_send, sends over sock.
    Receives from sock, decrypts with key_recv, prints to stdout.
    Both directions run concurrently (use threading).
    
    key_send:      32-byte key for outbound messages
    key_recv:      32-byte key for inbound messages  
    nonce_material: 12-byte base nonce (XOR'd with sequence number)
    identity:      "client" or "server" — used as sender_id in header
    """
    raise NotImplementedError
```

- [ ] **Step 4: Commit**

```bash
git add protocol/
git commit -m "chore: add protocol stubs (handshake, replay, channel)"
```

---

### Task 6: Utilities and Entry Points

**Files:**
- Create: `utilities/channel_setup.py`
- Create: `server.py`
- Create: `client.py`

- [ ] **Step 1: Write `utilities/channel_setup.py`**

```python
import socket

def create_server_socket(host: str, port: int) -> socket.socket:
    """Creates a TCP server socket, binds, listens, accepts one connection.
    
    Blocks until a client connects. Returns the connected socket.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"[server] Listening on {host}:{port} ...")
    conn, addr = server.accept()
    print(f"[server] Connection from {addr}")
    return conn

def create_client_socket(host: str, port: int) -> socket.socket:
    """Creates a TCP client socket and connects to host:port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[client] Connected to {host}:{port}")
    return sock
```

- [ ] **Step 2: Write `server.py`**

```python
import argparse
import json
from utilities.channel_setup import create_server_socket
from protocol.handshake import perform_handshake
from protocol.channel import run

def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChannel server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    psk = config["psk"].encode()
    identity = "server"

    sock = create_server_socket(args.host, args.port)
    key_c2s, key_s2c, nonce_material = perform_handshake(sock, psk, identity)
    run(sock, key_send=key_s2c, key_recv=key_c2s, nonce_material=nonce_material, identity=identity)

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Write `client.py`**

```python
import argparse
import json
from utilities.channel_setup import create_client_socket
from protocol.handshake import perform_handshake
from protocol.channel import run

def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChannel client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--config", default="config.json")
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    psk = config["psk"].encode()
    identity = "client"

    sock = create_client_socket(args.host, args.port)
    key_c2s, key_s2c, nonce_material = perform_handshake(sock, psk, identity)
    run(sock, key_send=key_c2s, key_recv=key_s2c, nonce_material=nonce_material, identity=identity)

if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Commit**

```bash
git add utilities/ server.py client.py
git commit -m "chore: add utilities and thin entry points (server, client)"
```

---

### Task 7: Test Infrastructure

**Files:**
- Create: `tests/sha256/vectors.json`
- Create: `tests/sha256/test_sha256.py`
- Create: `tests/hmac/vectors.json`
- Create: `tests/hmac/test_hmac.py`
- Create: `tests/hkdf/vectors.json`
- Create: `tests/hkdf/test_hkdf.py`
- Create: `tests/x25519/vectors.json`
- Create: `tests/x25519/test_x25519.py`
- Create: `tests/chacha20/vectors.json`
- Create: `tests/chacha20/test_chacha20.py`
- Create: `tests/poly1305/vectors.json`
- Create: `tests/poly1305/test_poly1305.py`
- Create: `tests/aead/vectors.json`
- Create: `tests/aead/test_aead.py`
- Create: `tests/run_tests.py`

#### SHA-256

- [ ] **Step 1: Write `tests/sha256/vectors.json`** (from FIPS 180-4 §B.1 and §B.2)

```json
[
  {
    "description": "FIPS 180-4 §B.1 — one-block message",
    "input_hex": "616263",
    "output_hex": "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469001d0087b8b3a4d63"
  },
  {
    "description": "FIPS 180-4 §B.2 — two-block message",
    "input_hex": "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
    "output_hex": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
  }
]
```

- [ ] **Step 2: Write `tests/sha256/test_sha256.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.sha256 import sha256

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_sha256_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        msg = bytes.fromhex(v['input_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = sha256(msg)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_sha256_vectors()
    print(f"SHA-256  ... PASSED ({passed}/{total} vectors)")
```

#### HMAC

- [ ] **Step 3: Write `tests/hmac/vectors.json`** (from RFC 2104 Appendix)

```json
[
  {
    "description": "RFC 2104 test case 1",
    "key_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "data_hex": "4869205468657265",
    "output_hex": "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
  },
  {
    "description": "RFC 2104 test case 2 — key shorter than block",
    "key_hex": "4a656665",
    "data_hex": "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
    "output_hex": "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964a66f8"
  },
  {
    "description": "RFC 2104 test case 3 — combined data",
    "key_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "data_hex": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
    "output_hex": "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
  }
]
```

- [ ] **Step 4: Write `tests/hmac/test_hmac.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.hmac_impl import hmac

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_hmac_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        data = bytes.fromhex(v['data_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = hmac(key, data)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_hmac_vectors()
    print(f"HMAC     ... PASSED ({passed}/{total} vectors)")
```

#### HKDF

- [ ] **Step 5: Write `tests/hkdf/vectors.json`** (from RFC 5869 Appendix A)

```json
[
  {
    "description": "RFC 5869 A.1 — basic",
    "ikm_hex": "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    "salt_hex": "000102030405060708090a0b0c",
    "info_hex": "f0f1f2f3f4f5f6f7f8f9",
    "length": 42,
    "okm_hex": "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
  },
  {
    "description": "RFC 5869 A.2 — longer inputs",
    "ikm_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
    "salt_hex": "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
    "info_hex": "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
    "length": 82,
    "okm_hex": "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
  }
]
```

- [ ] **Step 6: Write `tests/hkdf/test_hkdf.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.hkdf import hkdf

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_hkdf_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        ikm = bytes.fromhex(v['ikm_hex'])
        salt = bytes.fromhex(v['salt_hex'])
        info = bytes.fromhex(v['info_hex'])
        expected = bytes.fromhex(v['okm_hex'])
        result = hkdf(ikm, salt, info, v['length'])
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_hkdf_vectors()
    print(f"HKDF     ... PASSED ({passed}/{total} vectors)")
```

#### X25519

- [ ] **Step 7: Write `tests/x25519/vectors.json`** (from RFC 7748 §6.1)

```json
[
  {
    "description": "RFC 7748 §6.1 — test vector 1",
    "private_key_hex": "77076d0a7318a57d3c16c17251b26645df1fb2ce7ac81098d1fc2c88db3b70a",
    "public_key_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "peer_public_key_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "shared_secret_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  },
  {
    "description": "RFC 7748 §6.1 — test vector 2",
    "private_key_hex": "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    "public_key_hex": "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    "peer_public_key_hex": "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    "shared_secret_hex": "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  }
]
```

- [ ] **Step 8: Write `tests/x25519/test_x25519.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.x25519 import x25519

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_x25519_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        private = bytes.fromhex(v['private_key_hex'])
        peer_public = bytes.fromhex(v['peer_public_key_hex'])
        expected = bytes.fromhex(v['shared_secret_hex'])
        result = x25519(private, peer_public)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_x25519_vectors()
    print(f"X25519   ... PASSED ({passed}/{total} vectors)")
```

#### ChaCha20

- [ ] **Step 9: Write `tests/chacha20/vectors.json`** (from RFC 8439 §2.1.2 and §2.4.2)

```json
[
  {
    "description": "RFC 8439 §2.4.2 — encryption test vector",
    "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "nonce_hex": "000000000000004a00000000",
    "counter": 1,
    "plaintext_hex": "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    "ciphertext_hex": "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
  },
  {
    "description": "RFC 8439 §2.1.2 — block function test",
    "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "nonce_hex": "000000090000004a00000000",
    "counter": 1,
    "plaintext_hex": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "ciphertext_hex": "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
  }
]
```

- [ ] **Step 10: Write `tests/chacha20/test_chacha20.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.chacha20 import chacha20

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_chacha20_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        nonce = bytes.fromhex(v['nonce_hex'])
        counter = v['counter']
        plaintext = bytes.fromhex(v['plaintext_hex'])
        expected = bytes.fromhex(v['ciphertext_hex'])
        result = chacha20(key, nonce, counter, plaintext)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_chacha20_vectors()
    print(f"ChaCha20 ... PASSED ({passed}/{total} vectors)")
```

#### Poly1305

- [ ] **Step 11: Write `tests/poly1305/vectors.json`** (from RFC 8439 §2.5.2)

```json
[
  {
    "description": "RFC 8439 §2.5.2 — test vector",
    "key_hex": "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
    "message_hex": "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
    "tag_hex": "a8061dc1305136c6c22b8baf0c0127a9"
  },
  {
    "description": "RFC 8439 §2.5.2 — zero key",
    "key_hex": "0000000000000000000000000000000000000000000000000000000000000000",
    "message_hex": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "tag_hex": "00000000000000000000000000000000"
  }
]
```

- [ ] **Step 12: Write `tests/poly1305/test_poly1305.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.poly1305 import poly1305

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_poly1305_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        message = bytes.fromhex(v['message_hex'])
        expected = bytes.fromhex(v['tag_hex'])
        result = poly1305(key, message)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_poly1305_vectors()
    print(f"Poly1305 ... PASSED ({passed}/{total} vectors)")
```

#### AEAD

- [ ] **Step 13: Write `tests/aead/vectors.json`** (from RFC 8439 §2.8.2)

```json
[
  {
    "description": "RFC 8439 §2.8.2 — AEAD construction test vector",
    "key_hex": "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    "nonce_hex": "070000004041424344454647",
    "aad_hex": "50515253c0c1c2c3c4c5c6c7",
    "plaintext_hex": "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
    "ciphertext_hex": "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
    "tag_hex": "1ae10b594f09e26a7e902ecbd0600691"
  }
]
```

- [ ] **Step 14: Write `tests/aead/test_aead.py`**

```python
import json
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from primitives.aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_aead_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        nonce = bytes.fromhex(v['nonce_hex'])
        aad = bytes.fromhex(v['aad_hex'])
        plaintext = bytes.fromhex(v['plaintext_hex'])
        expected_ct = bytes.fromhex(v['ciphertext_hex'])
        expected_tag = bytes.fromhex(v['tag_hex'])

        ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ct, (
            f"FAIL ciphertext [{v['description']}]\n"
            f"  expected: {expected_ct.hex()}\n"
            f"  got:      {ciphertext.hex()}"
        )
        assert tag == expected_tag, (
            f"FAIL tag [{v['description']}]\n"
            f"  expected: {expected_tag.hex()}\n"
            f"  got:      {tag.hex()}"
        )

        recovered = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
        assert recovered == plaintext, (
            f"FAIL decrypt [{v['description']}]\n"
            f"  expected: {plaintext.hex()}\n"
            f"  got:      {recovered.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_aead_vectors()
    print(f"AEAD     ... PASSED ({passed}/{total} vectors)")
```

#### Test Runner

- [ ] **Step 15: Write `tests/run_tests.py`**

```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from tests.sha256.test_sha256 import test_sha256_vectors
from tests.hmac.test_hmac import test_hmac_vectors
from tests.hkdf.test_hkdf import test_hkdf_vectors
from tests.x25519.test_x25519 import test_x25519_vectors
from tests.chacha20.test_chacha20 import test_chacha20_vectors
from tests.poly1305.test_poly1305 import test_poly1305_vectors
from tests.aead.test_aead import test_aead_vectors

SUITES = [
    ("SHA-256  ", test_sha256_vectors),
    ("HMAC     ", test_hmac_vectors),
    ("HKDF     ", test_hkdf_vectors),
    ("X25519   ", test_x25519_vectors),
    ("ChaCha20 ", test_chacha20_vectors),
    ("Poly1305 ", test_poly1305_vectors),
    ("AEAD     ", test_aead_vectors),
]

def main():
    all_passed = True
    for name, fn in SUITES:
        try:
            passed, total = fn()
            print(f"{name} ... PASSED ({passed}/{total} vectors)")
        except AssertionError as e:
            print(f"{name} ... FAILED\n  {e}")
            all_passed = False
        except NotImplementedError:
            print(f"{name} ... NOT IMPLEMENTED")
            all_passed = False

    print()
    if all_passed:
        print("All tests passed ✓")
    else:
        print("Some tests failed ✗")
        sys.exit(1)

if __name__ == '__main__':
    main()
```

- [ ] **Step 16: Add `__init__.py` to test directories**

```bash
touch tests/__init__.py tests/sha256/__init__.py tests/hmac/__init__.py tests/hkdf/__init__.py tests/x25519/__init__.py tests/chacha20/__init__.py tests/poly1305/__init__.py tests/aead/__init__.py
```

- [ ] **Step 17: Run the test runner to confirm it loads correctly (all NOT IMPLEMENTED is expected)**

```bash
python tests/run_tests.py
```

Expected output:
```
SHA-256   ... NOT IMPLEMENTED
HMAC      ... NOT IMPLEMENTED
HKDF      ... NOT IMPLEMENTED
X25519    ... NOT IMPLEMENTED
ChaCha20  ... NOT IMPLEMENTED
Poly1305  ... NOT IMPLEMENTED
AEAD      ... NOT IMPLEMENTED

Some tests failed ✗
```

- [ ] **Step 18: Commit**

```bash
git add tests/
git commit -m "chore: add test infrastructure with official RFC/FIPS test vectors"
```

---

### Task 8: Documentation

**Files:**
- Create: `README.md`
- Create: `docs/AI_USAGE.md`
- Create: `docs/diagrams/primitives.md`
- Create: `docs/diagrams/handshake.md`
- Create: `docs/diagrams/messaging.md`

- [ ] **Step 1: Write `docs/diagrams/primitives.md`**

```markdown
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
             ├──► aead.py ──────────────────────► channel.py
poly1305.py ─┘      │
                     └──► replay.py (sequence guard)
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
```

- [ ] **Step 2: Write `docs/diagrams/handshake.md`** — copy the Phase A diagram from README verbatim (already designed, see README draft)

- [ ] **Step 3: Write `docs/diagrams/messaging.md`** — copy the Phase B diagram from README verbatim

- [ ] **Step 4: Write `docs/AI_USAGE.md`**

```markdown
# AI Usage Statement

## Tools Used
- Claude (Anthropic) — used throughout the project

## What AI Helped With
- Project structure and file layout decisions
- Function stub interfaces (signatures, type hints, docstrings) — agreed before implementation
- `utilities/channel_setup.py` — TCP socket boilerplate
- `server.py` and `client.py` — thin orchestrator structure and argparse setup
- `tests/run_tests.py` — test runner scaffolding
- Test vector JSON files — format design (values sourced directly from RFCs by the team)
- `README.md` first draft — reviewed, edited, and owned by the team
- Debugging assistance and concept clarification during implementation
- This document's structure

## What the Team Wrote Without AI
- All 7 primitive implementations (`primitives/*.py` function bodies)
- `protocol/handshake.py` — Phase A handshake logic
- `protocol/channel.py` — Phase B secure messaging loop
- `protocol/replay.py` — sequence number replay guard
- All test logic in `tests/*/test_*.py`
- Design report and oral defense preparation

## Notes
The oral defense (40% of grade) requires live explanation and modification of code.
Every line in `primitives/` and `protocol/` was written and is understood by the team member
who owns it.
```

- [ ] **Step 5: Write `README.md`** — using the provided README draft as base, update file paths to match final structure (`primitives/` instead of `crypto/`, per-primitive test folders)

- [ ] **Step 6: Commit**

```bash
git add docs/ README.md
git commit -m "docs: add README, AI usage statement, and architecture diagrams"
```

---

## Phase 2 — Implementation (Students Work Independently)

After Phase 1 is committed, students split. The workflow for each primitive is identical:

1. Read the relevant RFC section end-to-end before writing any code
2. Run `python tests/run_tests.py` — confirm your primitive shows `NOT IMPLEMENTED`
3. Write your implementation in the primitive file
4. Run tests — iterate until `PASSED`
5. Commit: `feat: implement sha256 per FIPS 180-4`

### Student 1 Implementation Order

Work in this order — each primitive depends on the one above:

| Step | File | RFC Section to Read |
|------|------|---------------------|
| 1 | `primitives/sha256.py` | FIPS 180-4 §4.1.2 (functions), §4.2.2 (constants), §6.2.2 (computation) |
| 2 | `primitives/hmac_impl.py` | RFC 2104 §2 |
| 3 | `primitives/hkdf.py` | RFC 5869 §2.2 (extract), §2.3 (expand) |
| 4 | `primitives/x25519.py` | RFC 7748 §5 (field arithmetic, ladder, clamping) |
| 5 | `protocol/handshake.py` | README Phase A diagram — all primitives must pass tests first |

### Student 2 Implementation Order

ChaCha20 and Poly1305 are independent — either can go first:

| Step | File | RFC Section to Read |
|------|------|---------------------|
| 1 | `primitives/chacha20.py` | RFC 8439 §2.1 (quarter round), §2.2 (block), §2.3 (encrypt) |
| 2 | `primitives/poly1305.py` | RFC 8439 §2.5 (key generation + MAC computation) |
| 3 | `primitives/aead.py` | RFC 8439 §2.8 (construction) |
| 4 | `protocol/replay.py` | Simple — strictly-increasing sequence counter |
| 5 | `protocol/channel.py` | README Phase B diagram — all primitives must pass tests first |

---

## Phase 3 — Integration

Once both students have passing tests on all their primitives:

- [ ] **Step 1:** Both run `python tests/run_tests.py` — all 7 must show PASSED
- [ ] **Step 2:** Create a local `config.json` from `config.json.example` with a shared PSK
- [ ] **Step 3:** In terminal A: `python server.py --host 127.0.0.1 --port 5000`
- [ ] **Step 4:** In terminal B: `python client.py --host 127.0.0.1 --port 5000`
- [ ] **Step 5:** Send messages in both directions, verify they appear correctly
- [ ] **Step 6:** Kill terminal B mid-session, verify server handles disconnect gracefully
- [ ] **Step 7:** Final commit: `feat: end-to-end integration complete`
