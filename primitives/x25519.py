# Note to implement this,  tried to mimic C fucntions and methods introduced in the M. Kleppmann Tutorial.

# define constants for the curve25519
P    = 2**255 - 19   # the prime
A    = 486662        # the curve parameter
A24  = 121665        # (A - 2) / 4, used inside the ladder
BITS = 255           # This represent the number of bits in the field, which is 255 for curve25519
BASE_POINT_U = bytes([9]) + bytes(31) # Only need U coodinate of the base point, which is 9 followed by 31 zero bytes

def x25519(scalar_hex: bytes, u_coord_hex: bytes = BASE_POINT_U) -> bytes: # uses by default the base point U coordinate if not provided
        """ Used for key generation using elliptic curve arithmetic"""
        k = _clamp_scalar(scalar_hex)               # clamp and decode scalar to int
        u_int = _decode_u_coordinate(u_coord_hex)   # decode u coordinate to int
        result = _montgomery_ladder(k, u_int)       # run the ladder, get int back
        return _encode_u_coordinate(result)         # encode result as 32 bytes


def _clamp_scalar(scalar: bytes) -> int:
    clamped = bytearray(scalar)
    # clear the bottom 3 bits of the first byte
    clamped[0] &= 0b11111000
    # clear  the top bit of the last byte:
    clamped[31] &= 0b01111111
    # set the second-to-top bit of the last byte
    clamped[31] |= 0b01000000
    return int.from_bytes(clamped, 'little') # use little-endian

def _decode_u_coordinate(u: bytes) -> int:
    # Takes 32 bytes, masks the top bit of the last byte, then decodes as little-endian integer.
    u = bytearray(u)
    u[31] &= 0b01111111
    return int.from_bytes(u, 'little')

def _encode_u_coordinate(u: int) -> bytes:
    u = u % P                        # reduce mod p
    return u.to_bytes(32, 'little')  # use little-endian


def _cswap(swap: int, x2: int, x3: int) -> tuple: # swap if 1, return same if 0, used in ladder
    if swap:
        return x3, x2  
    return x2, x3      # unchanged


def _montgomery_ladder(scalar: int, u: int) -> int:

    # start by defining variables in the loop
    x1 = u
    x2 = 1
    z2 = 0
    x3 = u
    z3 = 1
    swap = 0

    for t in range(BITS-1, -1, -1):
        kt = (scalar >> t) & 1      # extract bit t of scalar
        swap = swap ^ kt                  # update swap
        (x2, x3) = _cswap(swap, x2, x3)
        (z2, z3) = _cswap(swap, z2, z3)
        swap = kt                   # save current bit

        A  = (x2 + z2) % P
        AA = (A * A)     % P
        B  = (x2 - z2) % P
        BB = (B * B)      % P
        E  = (AA - BB)    % P
        C  = (x3 + z3) % P
        D  = (x3 - z3) % P
        DA = (D * A)      % P
        CB = (C * B)      % P
        x3 = pow(DA + CB, 2, P)
        z3 = x1 * pow(DA - CB, 2, P) % P
        x2 = (AA * BB)               % P
        z2 = E * (AA + A24 * E)      % P

    (x2, x3) = _cswap(swap, x2, x3)
    (z2, z3) = _cswap(swap, z2, z3)

    # find modular inverse of z2 using Fermat's little theorem
    inv_z2 = pow(z2, P - 2, P) 
    # then multiply by x2 to get the final result 
    return (x2 * inv_z2) % P