import sys

from tests.sha256.test_sha256 import test_sha256_vectors
from tests.hmac.test_hmac import test_hmac_vectors
from tests.hkdf.test_hkdf import test_hkdf_vectors
from tests.x25519.test_x25519 import test_x25519_vectors
from tests.chacha20.test_chacha20 import test_chacha20_vectors
from tests.poly1305.test_poly1305 import test_poly1305_vectors
from tests.aead.test_aead import test_aead_vectors

SUITES = [
    ("SHA-256  ", test_sha256_vectors),
    ("HMAC     ", test_hmac_vectors),
    ("HKDF     ", test_hkdf_vectors),
    ("X25519   ", test_x25519_vectors),
    ("ChaCha20 ", test_chacha20_vectors),
    ("Poly1305 ", test_poly1305_vectors),
    ("AEAD     ", test_aead_vectors),
]

def main():
    all_passed = True
    for name, fn in SUITES:
        try:
            passed, total = fn()
            print(f"{name} ... PASSED ({passed}/{total} vectors)")
        except AssertionError as e:
            print(f"{name} ... FAILED\n  {e}")
            all_passed = False
        except NotImplementedError:
            print(f"{name} ... NOT IMPLEMENTED")
            all_passed = False

    print()
    if all_passed:
        print("All tests passed ✓")
    else:
        print("Some tests failed ✗")
        sys.exit(1)

if __name__ == '__main__':
    main()
