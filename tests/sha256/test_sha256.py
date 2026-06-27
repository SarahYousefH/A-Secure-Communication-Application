import json
import os
import pytest
from primitives.sha256 import sha256

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_sha256_vectors(vector):
    msg = bytes.fromhex(vector['input_hex'])
    expected = bytes.fromhex(vector['output_hex'])
    result = sha256(msg)
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
    for v in vectors:
        msg = bytes.fromhex(v['input_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = sha256(msg)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
    print(f"SHA-256  ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
