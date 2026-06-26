from primitives.chacha20 import chacha20
from primitives.poly1305 import poly1305
import hmac

def _pad16(data: bytes) -> bytes:
    """Return zero padding so the length becomes a multiple of 16 bytes."""
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(data) % 16))


def _build_mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    """Construct the input authenticated by Poly1305 according to RFC 8439."""
    # AAD || padding || ciphertext || padding || lengths

    # Start building the authenticated data:
    # The AAD is authenticated but is transmitted in plaintext
    mac_data = aad

    # Poly1305 processes data in 16-byte blocks
    # If the AAD isn't already a multiple of 16 bytes, pad with zeros
    mac_data += _pad16(aad)

    # Append the ciphertext after the padded AAD
    mac_data += ciphertext

    # Pad the ciphertext to the next 16-byte boundary
    mac_data += _pad16(ciphertext)

    # RFC 8439 appends the lengths of the AAD and ciphertext
    # as two 64-bit little-endian integers
    mac_data += len(aad).to_bytes(8, "little")
    mac_data += len(ciphertext).to_bytes(8, "little")

    return mac_data


def _validate_inputs(key: bytes, nonce: bytes):
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes.")
    if len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes.")


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

    _validate_inputs(key, nonce)

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
    mac_data = _build_mac_data(aad, ciphertext)

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

    _validate_inputs(key, nonce)

    # Generate the one-time Poly1305 key
    # Both the sender and receiver have:
    #   the same key and the same nonce
    # So they'll both generate the same 32-byte Poly1305 key
    poly_key = chacha20(
        key,
        nonce,
        0,
        b"\x00" * 32
    )[:32]

    mac_data = _build_mac_data(aad, ciphertext)

    # Compute the expected authentication tag
    expected_tag = poly1305(
        poly_key,
        mac_data
    )

    # Verify the tag using a constant-time comparison
    # compare_digest() always compares every byte, making it resistant to timing attacks
    if not hmac.compare_digest(expected_tag, tag):
        raise ValueError("Authentication failed")

    # Authentication succeeded.
    # Decrypt using the same ChaCha20 key, nonce, and counter
    plaintext = chacha20(
        key,
        nonce,
        1,
        ciphertext
    )

    return plaintext

