
# Fisrt we define initial hash values which are constans:

H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19,
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# define functions used in the algorithim
def Ch(x, y, z):
    return ((x & y) ^ (~x & z)) & 0xFFFFFFFF

def Maj(x, y, z):
    return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF

def rotr(x, n): # this function rotates the bits of x to the right by n positions
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sigma0_upper(x):   # Σ0
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def sigma1_upper(x):   # Σ1
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def sigma0_lower(x):   # σ0
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def sigma1_lower(x):   # σ1
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def sha256(message: bytes) -> bytes:
    """Returns the 32-byte SHA-256 digest of message per FIPS 180-4."""
    # Start by padding message to 64 bytes
    hash_values = list(H)  # start withthe 8 hardcoded constants
    preprocessed = _sha256_pad(message)
    # split the padded message into 64 blocks
    blocks = [preprocessed [i:i+64] for i in range(0, len(preprocessed), 64)] # we take every 64 bytes for a block, number of block = len(preprocessed) // 64
    # send each part of message to the block 
    for block in blocks:
        hash_values = _sha256_block(hash_values, block)
    
    # finally we return the hash values as a single 32-byte digest
    digest = b'' # empty binary string
    for word in hash_values:
        digest += word.to_bytes(4, 'big') # each words takes 4 bytes
    return digest

def _sha256_pad(message: bytes) -> bytes:
    """Pads the message to length 512 bits (64 bytes)."""
    # The idea here because we are using bytes and not bits throughout, this simplifies implemneation
    # The strcuctre is as follows: [ original message ] [ 0x80 ] [ zero bytes ] [ original length in bits  ( 8 bytes reserved for this)) ]
    length = len(message)           # length in bytes
    num_zeros = (56 - (length + 1)) % 64     # refer to l+ 1 + k = 448 mod 512
    message += b'\x80'              # append 1 byte
    message += b'\x00' * num_zeros  # append zero bytes
    message += (length * 8).to_bytes(8, 'big')  # the big endian 
    return message

def _sha256_block(hash_values: list, block: bytes) -> list[bytes]:
    """Splits the message into 64-byte blocks."""
    # Intialize intrmediate registers
    a, b, c, d, e, f, g, h = hash_values
    # divide the message into 16 32-bit words
    W = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]  # 16 words of 4 bytes each
    # apply the compression function to each block
    W = _message_schedule(W)   # Update the words of this block 
    new_state = _compression_function(a, b, c, d, e, f, g, h, W)

    # compute intermediate hash value
    new_hash = [0] * 8 
    for i in range(8):
        new_hash[i] = (hash_values[i] + new_state[i]) & 0xFFFFFFFF
                    
    return new_hash

def _message_schedule(W: list[int]) -> list[int]:
    # expand the 16 words into 64 words
    for i in range(16, 64):
        s0 = sigma0_lower(W[i - 15])
        s1 = sigma1_lower(W[i - 2])
        W.append((s0 + W[i - 7] + s1 + W[i - 16]) & 0xFFFFFFFF) # note : 0xFFFFFFFF  forces the result to stay within 32 bits 
    return W

def _compression_function(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, W: list[int], ) -> tuple[int]:
    for i in range(0, 64):
        T1 = (h + sigma1_upper(e) + Ch(e, f, g) + K[i] + W[i]) & 0xFFFFFFFF
        T2 = (sigma0_upper(a) + Maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
    return [a, b, c, d, e, f, g, h] 

