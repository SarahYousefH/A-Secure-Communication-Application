from primitives.hmac_impl import hmac

def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Returns `length` bytes of derived key material per RFC 5869.

    Performs HKDF-Extract followed by HKDF-Expand.
    length must be <= 255 * 32 (HashLen for SHA-256).
    """
    raise NotImplementedError
