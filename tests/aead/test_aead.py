import json
import os
import pytest
from primitives.aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_aead_vectors(vector):
    key = bytes.fromhex(vector['key_hex'])
    nonce = bytes.fromhex(vector['nonce_hex'])
    aad = bytes.fromhex(vector['aad_hex'])
    plaintext = bytes.fromhex(vector['plaintext_hex'])
    expected_ct = bytes.fromhex(vector['ciphertext_hex'])
    expected_tag = bytes.fromhex(vector['tag_hex'])

    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    assert ciphertext == expected_ct, (
        f"FAIL ciphertext [{vector['description']}]\n"
        f"  expected: {expected_ct.hex()}\n"
        f"  got:      {ciphertext.hex()}"
    )
    assert tag == expected_tag, (
        f"FAIL tag [{vector['description']}]\n"
        f"  expected: {expected_tag.hex()}\n"
        f"  got:      {tag.hex()}"
    )

    recovered = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
    assert recovered == plaintext, (
        f"FAIL decrypt [{vector['description']}]\n"
        f"  expected: {plaintext.hex()}\n"
        f"  got:      {recovered.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
    for v in vectors:
        key = bytes.fromhex(v['key_hex'])
        nonce = bytes.fromhex(v['nonce_hex'])
        aad = bytes.fromhex(v['aad_hex'])
        plaintext = bytes.fromhex(v['plaintext_hex'])
        expected_ct = bytes.fromhex(v['ciphertext_hex'])
        expected_tag = bytes.fromhex(v['tag_hex'])

        ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
        assert ciphertext == expected_ct, (
            f"FAIL ciphertext [{v['description']}]\n"
            f"  expected: {expected_ct.hex()}\n"
            f"  got:      {ciphertext.hex()}"
        )
        assert tag == expected_tag, (
            f"FAIL tag [{v['description']}]\n"
            f"  expected: {expected_tag.hex()}\n"
            f"  got:      {tag.hex()}"
        )

        recovered = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
        assert recovered == plaintext, (
            f"FAIL decrypt [{v['description']}]\n"
            f"  expected: {plaintext.hex()}\n"
            f"  got:      {recovered.hex()}"
        )
    print(f"AEAD     ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
