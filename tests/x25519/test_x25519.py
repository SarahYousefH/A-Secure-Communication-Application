import json
import os
import pytest
from primitives.x25519 import x25519

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_x25519_vectors(vector):
    scalar = bytes.fromhex(vector['scalar_hex'])
    u = bytes.fromhex(vector['u_hex'])
    expected = bytes.fromhex(vector['output_hex'])
    result = x25519(scalar, u)
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
    for v in vectors:
        scalar = bytes.fromhex(v['scalar_hex'])
        u = bytes.fromhex(v['u_hex'])
        expected = bytes.fromhex(v['output_hex'])
        result = x25519(scalar, u)
        assert result == expected, (
            f"FAIL [{v['description']}]\n"
            f"  expected: {expected.hex()}\n"
            f"  got:      {result.hex()}"
        )
    print(f"X25519   ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
