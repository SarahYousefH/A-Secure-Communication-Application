def poly1305(key: bytes, message: bytes) -> bytes:
    """Returns the 16-byte Poly1305 MAC per RFC 8439 §2.5.

    key: 32 bytes (r || s), where r is the first 16 bytes (clamped)
    message: arbitrary length bytes
    """
    raise NotImplementedError

def _clamp_r(r: bytes) -> int:
    r = bytearray(r)

    r[3] &= 15
    r[7] &= 15
    r[11] &= 15
    r[15] &= 15

    r[4] &= 252
    r[8] &= 252
    r[12] &= 252

    return int.from_bytes(r, "little")

def _blocks(message: bytes):
    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        yield block
