import json
import os
import pytest
from primitives.hkdf import hkdf

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_hkdf_vectors(vector):
    ikm = bytes.fromhex(vector['ikm_hex'])
    salt = bytes.fromhex(vector['salt_hex'])
    info = bytes.fromhex(vector['info_hex'])
    expected = bytes.fromhex(vector['okm_hex'])
    result = hkdf(ikm, salt, info, vector['length'])
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
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
    print(f"HKDF     ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
