import json
import os
from primitives.x25519 import x25519

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_x25519_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        private = bytes.fromhex(v['private_key_hex'])
        peer_public = bytes.fromhex(v['peer_public_key_hex'])
        expected = bytes.fromhex(v['shared_secret_hex'])
        result = x25519(private, peer_public)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_x25519_vectors()
    print(f"X25519   ... PASSED ({passed}/{total} vectors)")
