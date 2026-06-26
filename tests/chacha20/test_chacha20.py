import json
import os
import pytest
from primitives.chacha20 import chacha20

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_chacha20_vectors(vector):
    key = bytes.fromhex(vector['key_hex'])
    nonce = bytes.fromhex(vector['nonce_hex'])
    counter = vector['counter']
    plaintext = bytes.fromhex(vector['plaintext_hex'])
    expected = bytes.fromhex(vector['ciphertext_hex'])
    result = chacha20(key, nonce, counter, plaintext)
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
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
    print(f"ChaCha20 ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
