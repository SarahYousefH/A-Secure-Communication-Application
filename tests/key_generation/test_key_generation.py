import json
import os
import pytest
from primitives.x25519 import x25519

def load_vectors():
    path = os.path.join(os.path.dirname(__file__), 'vectors.json')
    with open(path) as f:
        return json.load(f)

@pytest.mark.parametrize("vector", load_vectors(), ids=lambda v: v['description'])
def test_key_generation_vectors(vector):
    alice_private = bytes.fromhex(vector['alice_private_hex'])
    alice_public = bytes.fromhex(vector['alice_public_hex'])
    bob_private = bytes.fromhex(vector['bob_private_hex'])
    bob_public = bytes.fromhex(vector['bob_public_hex'])
    expected_shared = bytes.fromhex(vector['shared_secret_hex'])

    assert x25519(alice_private) == alice_public, (
        f"FAIL [{vector['description']}] Alice's public key mismatch"
    )
    assert x25519(bob_private) == bob_public, (
        f"FAIL [{vector['description']}] Bob's public key mismatch"
    )

    shared_from_alice = x25519(alice_private, bob_public)
    shared_from_bob = x25519(bob_private, alice_public)

    assert shared_from_alice == expected_shared, (
        f"FAIL [{vector['description']}] Alice's shared secret mismatch\n"
        f"  expected: {expected_shared.hex()}\n"
        f"  got:      {shared_from_alice.hex()}"
    )
    assert shared_from_bob == expected_shared, (
        f"FAIL [{vector['description']}] Bob's shared secret mismatch\n"
        f"  expected: {expected_shared.hex()}\n"
        f"  got:      {shared_from_bob.hex()}"
    )

if __name__ == '__main__':
    vectors = load_vectors()
    for v in vectors:
        alice_private = bytes.fromhex(v['alice_private_hex'])
        alice_public = bytes.fromhex(v['alice_public_hex'])
        bob_private = bytes.fromhex(v['bob_private_hex'])
        bob_public = bytes.fromhex(v['bob_public_hex'])
        expected_shared = bytes.fromhex(v['shared_secret_hex'])

        assert x25519(alice_private) == alice_public, (
            f"FAIL [{v['description']}] Alice's public key mismatch"
        )
        assert x25519(bob_private) == bob_public, (
            f"FAIL [{v['description']}] Bob's public key mismatch"
        )
        assert x25519(alice_private, bob_public) == expected_shared, (
            f"FAIL [{v['description']}] Alice's shared secret mismatch"
        )
        assert x25519(bob_private, alice_public) == expected_shared, (
            f"FAIL [{v['description']}] Bob's shared secret mismatch"
        )
    print(f"KEY_GENERATION ... PASSED ({len(vectors)}/{len(vectors)} vectors)")
