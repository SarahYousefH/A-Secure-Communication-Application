import json
import os
from primitives.sha256 import sha256

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_sha256_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        msg = bytes.fromhex(v['input_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = sha256(msg)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_sha256_vectors()
    print(f"SHA-256  ... PASSED ({passed}/{total} vectors)")
