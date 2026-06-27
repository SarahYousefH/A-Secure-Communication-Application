import json
import os
import pytest
from primitives.poly1305 import poly1305

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_poly1305_vectors(vector):
    key = bytes.fromhex(vector['key_hex'])
    message = bytes.fromhex(vector['message_hex'])
    expected = bytes.fromhex(vector['tag_hex'])
    result = poly1305(key, message)
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
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
    print(f"Poly1305 ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
