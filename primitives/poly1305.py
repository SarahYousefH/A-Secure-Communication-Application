def poly1305(key: bytes, message: bytes) -> bytes:
    """Returns the 16-byte Poly1305 MAC per RFC 8439 §2.5.

    key: 32 bytes (r || s), where r is the first 16 bytes (clamped)
    message: arbitrary length bytes
    """
    raise NotImplementedError
