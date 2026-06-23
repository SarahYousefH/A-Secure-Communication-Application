import struct

CHACHA_CONSTANTS = (
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574,
)

def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Returns one 64-byte ChaCha20 keystream block per RFC 8439 §2.1.

    key: 32 bytes
    counter: 32-bit unsigned integer
    nonce: 12 bytes
    """
    """ 1. Create the state: At this point state contains 16 numbers:

        0  1  2  3   -> constants
        4  5  6  7
        8  9 10 11   -> key
        12          -> counter
        13 14 15    -> nonce """

    state = _create_state(key, counter, nonce)

    """ 2. Make a working copy because ChaCha20 performs operations on a copy 
        and later adds the original state back. """

    working = state.copy()

    """ 3. Run 20 rounds: (For loop 10 times)
        Each loop performs:
        4 column rounds
        4 diagonal rounds
        which equals 2 rounds.
        10 × 2 = 20 rounds."""

    for _ in range(10):
        # Column rounds:
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)

        # Diagonal rounds:
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    """ 4. Add original state back:
        (required by RFC 8439) """

    for i in range(16):
        working[i] = (working[i] + state[i]) & 0xffffffff

    """ 5. Convert back to bytes:
        - < = little-endian
        - 16I = 16 unsigned 32-bit integers
        - 16 × 4 bytes = 64 bytes = (Exactly one ChaCha20 block)"""
    
    return struct.pack("<16I", *working)


def chacha20(key: bytes, nonce: bytes, counter: int, data: bytes) -> bytes:
    """Returns ChaCha20 keystream XOR'd with data per RFC 8439 §2.4.

    key: 32 bytes
    nonce: 12 bytes
    counter: initial block counter (0 for AEAD, 1 for raw encryption)
    data: plaintext or ciphertext of any length
    """
    raise NotImplementedError

def _rotl32(v: int, n: int) -> int:
    """Rotate left"""
    return ((v << n) & 0xffffffff) | (v >> (32 - n))

def _quarter_round(state, a, b, c, d):
    """RFC:

    a += b; d ^= a; d <<< 16
    c += d; b ^= c; b <<< 12
    a += b; d ^= a; d <<< 8
    c += d; b ^= c; b <<< 7
    """
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

def _create_state(key: bytes, counter: int, nonce: bytes):
    """Convert key"""
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))

    """ ChaCha20 state is:
    
    constant constant constant constant
    key      key      key      key
    key      key      key      key
    counter  nonce    nonce    nonce
    """
    return [
        *CHACHA_CONSTANTS,
        *key_words,
        counter,
        *nonce_words,
    ]
