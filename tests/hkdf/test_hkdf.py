import json
import os
from primitives.hkdf import hkdf

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_hkdf_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        ikm = bytes.fromhex(v['ikm_hex'])
        salt = bytes.fromhex(v['salt_hex'])
        info = bytes.fromhex(v['info_hex'])
        expected = bytes.fromhex(v['okm_hex'])
        result = hkdf(ikm, salt, info, v['length'])
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_hkdf_vectors()
    print(f"HKDF     ... PASSED ({passed}/{total} vectors)")
