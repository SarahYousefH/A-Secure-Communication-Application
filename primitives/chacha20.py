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

import struct

CHACHA_CONSTANTS = (
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
)

def _rotl32(v: int, n: int) -> int:
    return ((v << n) & 0xffffffff) | (v >> (32 - n))

def _quarter_round(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xffffffff
    state[d] ^= state[a]
    state[d] = _rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xffffffff
    state[b] ^= state[c]
    state[b] = _rotl32(state[b], 7)
