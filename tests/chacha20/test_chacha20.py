import json
import os
import pytest
from primitives.chacha20 import chacha20, chacha20_block, _create_state, _quarter_round


def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)


@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_chacha20_vectors(vector):

    vtype = vector["type"]

    # -----------------------------
    # Quarter round test
    # -----------------------------
    if vtype == "quarter_round":
        state = [int(x, 16) for x in vector["input"]]
        expected = [int(x, 16) for x in vector["expected"]]

        _quarter_round(state, 0, 1, 2, 3)
        assert state == expected
        return

    # -----------------------------
    # State creation test
    # -----------------------------
    if vtype == "create_state":
        key = bytes.fromhex(vector['key_hex'])
        nonce = bytes.fromhex(vector['nonce_hex'])
        counter = vector['counter']

        state = _create_state(key, counter, nonce)
        expected = [int(x, 16) for x in vector['expected_state']]

        assert state == expected
        return

    # -----------------------------
    # Block function test
    # -----------------------------
    if vtype == "block":
        key = bytes.fromhex(vector['key_hex'])
        nonce = bytes.fromhex(vector['nonce_hex'])
        counter = vector['counter']

        result = chacha20_block(key, counter, nonce)
        expected = bytes.fromhex(vector['block_hex'])

        assert result == expected
        return

    # -----------------------------
    # Encryption test (your original style)
    # -----------------------------
    if vtype == "encrypt":
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
        return

    # -----------------------------
    # Empty plaintext test
    # -----------------------------
    if vtype == "empty":
        key = bytes.fromhex(vector['key_hex'])
        nonce = bytes.fromhex(vector['nonce_hex'])
        counter = vector['counter']
        plaintext = b""
        expected = b""

        result = chacha20(key, nonce, counter, plaintext)
        assert result == expected
        return


# -----------------------------
# CLI runner 
# -----------------------------
if __name__ == '__main__':
    vectors = load_vectors()

    for v in vectors:
        vtype = v["type"]

        if vtype == "encrypt":
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

    print(f"ChaCha20 ... PASSED ({len(vectors)}/{len(vectors)})")
