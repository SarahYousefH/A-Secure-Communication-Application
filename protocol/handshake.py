import socket
from primitives.x25519 import x25519
from primitives.hmac_impl import hmac
from primitives.hkdf import hkdf


# Todo: make a test for this 

def generate_keypair() -> tuple[bytes, bytes]:
    """Returns (private_key, public_key) — both 32 bytes.

    private_key is 32 random bytes (clamped per RFC 7748 §5).
    public_key is the corresponding X25519 public key.
    """
    raise NotImplementedError

def perform_handshake(sock: socket.socket, psk: bytes, identity: str) -> tuple[bytes, bytes, bytes]:
    """Performs the Phase A handshake and returns session keys.

    Executes: ephemeral key exchange (X25519) + mutual authentication (HMAC)
    + key derivation (HKDF).

    identity: "client" or "server" — determines send/receive order

    Returns: (key_c2s, key_s2c, nonce_material)
        key_c2s:        32 bytes — ChaCha20 key for client->server messages
        key_s2c:        32 bytes — ChaCha20 key for server->client messages
        nonce_material: 12 bytes — base nonce XOR'd with sequence number per message

    Raises RuntimeError if peer authentication fails.
    """
    raise NotImplementedError
