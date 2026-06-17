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
