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

    # Generate the one-time Poly1305 key
    poly_key = chacha20(
        key,
        nonce,
        0,
        b"\x00" * 32
    )[:32]

    # Encrypt the plaintext using ChaCha20
    #   Counter 0 was already used to create the MAC key
    #   The RFC says actual encryption starts at counter = 1
    ciphertext = chacha20(
        key,
        nonce,
        1,
        plaintext
    )

    # Additional Authenticated Data (authenticated but not encrypted)
    mac_data = aad

    # Poly1305 processes data in 16-byte blocks
    # If the AAD isn't already a multiple of 16 bytes, pad with zeros
    if len(aad) % 16 != 0:
        mac_data += b"\x00" * (16 - (len(aad) % 16))

    # append the encrypted message
    mac_data += ciphertext

    # Pad the ciphertext (Poly1305 needs multiples of 16 bytes)
    if len(ciphertext) % 16 != 0:
        mac_data += b"\x00" * (16 - (len(ciphertext) % 16))

    # Append the lengths of the AAD and ciphertext (8 bytes each)
    mac_data += len(aad).to_bytes(8, "little")
    mac_data += len(ciphertext).to_bytes(8, "little")

    # Compute the authentication tag
    tag = poly1305(poly_key, mac_data)

    return ciphertext, tag

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
