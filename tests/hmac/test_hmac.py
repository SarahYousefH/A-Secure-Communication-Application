import json
import os
from primitives.hmac_impl import hmac

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_hmac_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        data = bytes.fromhex(v['data_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = hmac(key, data)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_hmac_vectors()
    print(f"HMAC     ... PASSED ({passed}/{total} vectors)")
