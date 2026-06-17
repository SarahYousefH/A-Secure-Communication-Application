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
