from primitives.hmac_impl import hmac, HASH_LEN


def hkdf(input_key_material: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Returns `length` bytes of derived key material per RFC 5869.

    Performs HKDF-Extract followed by HKDF-Expand.
    length must be <= 255 * 32 (HashLen for SHA-256).
    """
    raise NotImplementedError


def _hkdf_extract(salt: bytes, input_key_material: bytes) -> bytes:
      """Returns a pseudorandom key (PRK)"""
      # if salt is not provided, we use a string of zeros as the salt
      if salt is None:
        salt = bytes([0] * HASH_LEN)
      return hmac(salt, input_key_material)


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Returns output keying material (OKM)"""
    # Here we need to expand because we need more than 32 bytes for session keys
   

HKDF-Expand(PRK, info, L) -> OKM

   Options:
      Hash     a hash function; HashLen denotes the length of the
               hash function output in octets

Inputs:
      PRK      a pseudorandom key of at least HashLen octets
               (usually, the output from the extract step)
      info     optional context and application specific information
               (can be a zero-length string)
      L        length of output keying material in octets
               (<= 255*HashLen)

   Output:
      OKM      output keying material (of L octets)

   The output OKM is calculated as follows:

   N = ceil(L/HashLen)
   T = T(1) | T(2) | T(3) | ... | T(N)
   OKM = first L octets of T

   where:
   T(0) = empty string (zero length)
   T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
   T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
   T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
