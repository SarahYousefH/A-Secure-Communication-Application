from primitives.hmac_impl import hmac, HASH_LEN
import math

def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Returns `length` bytes of derived key material per RFC 5869.

    Performs HKDF-Extract followed by HKDF-Expand.
    length must be <= 255 * 32 (HashLen for SHA-256).
    """
    prk = _hkdf_extract(salt, input_key_material)
    okm = _hkdf_expand(prk, info, length)
    return okm


def _hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
      """Returns a pseudorandom key (PRK)"""
      # if salt is not provided, we use a string of zeros as the salt
      if salt is None:
        salt = bytes([0] * HASH_LEN)
      return hmac(salt, input_key_material)


def _hkdf_expand(prk: bytes, info: bytes, length_bytes: int) -> bytes:
    """Returns output keying material (OKM)"""
    # Here we need to expand because we need more than 32 bytes for session keys

    N = math.ceil(length_bytes / HASH_LEN)

    # define array of T values
    T = [b''] * (N+1) # we initialize the array with empty bytes
    
    for i in range(1,N+1): # we start from 1 because T[0] is empty
        T[i] = hmac(prk, T[i-1] + info + bytes([i]))

    T = b''.join(T[1:]) # join all the blocks
    OKM =  T[:length_bytes]
    return OKM