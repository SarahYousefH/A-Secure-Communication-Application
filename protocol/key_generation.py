import os

from primitives.x25519 import x25519


def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key) — both 32 bytes.

    private_key is 32 random bytes (clamped per RFC 7748 §5).
    public_key is the corresponding X25519 public key.
    """
    private_key = os.urandom(32)
    public_key = x25519(private_key)
    return private_key, public_key