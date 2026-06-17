import json
import os
from primitives.chacha20 import chacha20

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

def test_chacha20_vectors():
    vectors = load_vectors()
    passed = 0
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        nonce = bytes.fromhex(v['nonce_hex'])
        counter = v['counter']
        plaintext = bytes.fromhex(v['plaintext_hex'])
        expected = bytes.fromhex(v['ciphertext_hex'])
        result = chacha20(key, nonce, counter, plaintext)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
        passed += 1
    return passed, len(vectors)

if __name__ == '__main__':
    passed, total = test_chacha20_vectors()
    print(f"ChaCha20 ... PASSED ({passed}/{total} vectors)")
