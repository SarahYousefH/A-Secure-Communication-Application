import json
import os
from primitives.poly1305 import poly1305

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_poly1305_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        message = bytes.fromhex(v['message_hex'])
        expected = bytes.fromhex(v['tag_hex'])
        result = poly1305(key, message)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_poly1305_vectors()
    print(f"Poly1305 ... PASSED ({passed}/{total} vectors)")
