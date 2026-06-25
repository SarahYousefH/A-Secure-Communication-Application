# ----------------------------------------------------------
# Poly1305 Authentication
# ----------------------------------------------------------

# Poly1305 creates the authentication tag
def poly1305(key: bytes, message: bytes) -> bytes:
    """Returns the 16-byte Poly1305 MAC per RFC 8439 §2.5.

    key: 32 bytes (r || s), where r is the first 16 bytes (clamped)
    message: arbitrary length bytes
    """
    # validate key length to be exactly 32 bytes
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes.")

    # Poly1305 key = r || s
    # Split the 32-byte key into r and s
    # r is used during modular multiplication, while s is added at the end
    r = _clamp_r(key[:16])
    s = int.from_bytes(key[16:], "little")

    # Poly1305 performs arithmetic modulo: 2^130 - 5
    P = (1 << 130) - 5

    # Running accumulator used to process each message block
    acc = 0

    # Process each 16-byte block
    for block in _blocks(message):
        # Poly1305 treats each block as block || 0x01 before
        # converting it into a little-endian integer
        n = int.from_bytes(
            block + b"\x01",
            "little"
        )

        # Update accumulator modulo P

        # Incorporate the current message block
        acc = (acc + n) % P
        # Multiply by the secret value r modulo P
        acc = (acc * r) % P

    # The final authentication tag is computed by adding s
    # and reducing the result to the lower 128 bits.
    tag = (acc + s) % (1 << 128)

    # Poly1305 outputs a 16-byte authentication tag
    return tag.to_bytes(16, "little")

# ----------------------------------------------------------
# Helper Functions for Poly1305
# ----------------------------------------------------------

# Clamp r according to RFC 8439.
# Certain bits are cleared to guarantee the mathematical
# properties required by the Poly1305 algorithm
def _clamp_r(r: bytes) -> int:
    """Helper function to perform RFC clamping"""
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
    """ Splits the message into 16-byte chunks
    RFC Poly1305 treats every block as:

block || 0x01 before converting to an integer"""
    # Yield successive 16-byte blocks of the message
    # The final block may contain fewer than 16 bytes
    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        yield block
