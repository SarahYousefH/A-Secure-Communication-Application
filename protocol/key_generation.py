
# Todo: make a test for this  and genrate keypairs using the x25519 function and check that the public key is correct

def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key) — both 32 bytes.

    private_key is 32 random bytes (clamped per RFC 7748 §5).
    public_key is the corresponding X25519 public key.
    """
    raise NotImplementedError