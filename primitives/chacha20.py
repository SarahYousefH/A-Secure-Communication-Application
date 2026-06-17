def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Returns one 64-byte ChaCha20 keystream block per RFC 8439 §2.1.

    key: 32 bytes
    counter: 32-bit unsigned integer
    nonce: 12 bytes
    """
    raise NotImplementedError

def chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Returns ChaCha20 keystream XOR'd with data per RFC 8439 §2.4.

    key: 32 bytes
    nonce: 12 bytes
    counter: initial block counter (0 for AEAD, 1 for raw encryption)
    data: plaintext or ciphertext of any length
    """
    raise NotImplementedError
