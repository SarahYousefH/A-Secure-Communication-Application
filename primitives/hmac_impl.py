from primitives.sha256 import sha256


# define the HMAC constnts:
ipad = bytes([0x36] * 64)
opad = bytes([0x5c] * 64)

def hmac(key: bytes, message: bytes) -> bytes:
    """Returns the 32-byte HMAC-SHA-256 tag per RFC 2104."""
    if len(key) > 64:  # hash it if longer first shrink to 32 bytes
        key = sha256(key)
    key = key + b'\x00' * (64 - len(key)) # pad to 64
    final_message = sha256( xor_bytes (key, opad) + sha256(xor_bytes(key, ipad) + message) )
    return final_message

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))