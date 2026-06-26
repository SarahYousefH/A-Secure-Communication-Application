import json
import os
import pytest
from primitives.hmac_impl import hmac

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_hmac_vectors(vector):
    key = bytes.fromhex(vector['key_hex'])
    data = bytes.fromhex(vector['data_hex'])
    expected = bytes.fromhex(vector['output_hex'])
    result = hmac(key, data)
    assert result == expected, (
        f"FAIL [{vector['description']}]\n"
        f"  expected: {expected.hex()}\n"
        f"  got:      {result.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
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
    print(f"HMAC     ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
