import socket
from primitives.x25519 import x25519
from primitives.hmac_impl import hmac
from primitives.hkdf import hkdf
from protocol.key_generation import generate_keypair


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

    my_private, my_public = generate_keypair()
    # Send my public key to the peer
    sock.sendall(my_public)
    # Receive peer's public key
    peer_public = sock.recv(32)

    # Compute shared secret using X25519
    shared_secret = x25519(my_private, peer_public)


    # the psk is already read from the file and passed as bytes 
    my_hmac = hmac(psk, my_public)
    # receive the peer's HMAC
    peer_hmac = sock.recv(32)

    # Verify their HMAC
    try:
        _verify(peer_hmac, psk, peer_public)
    except ValueError:
        raise RuntimeError("Peer authentication failed")
    
    # derive keys using HKDF
    key_c2s, key_s2c, nonce_material = hkdf(shared_secret,
                                            salt=None,
                                            info=b"SecureChannel",
                                            length=32 + 32 + 12)  # total length for keys and nonce

    return key_c2s, key_s2c, nonce_material


def _verify(received_hmac: bytes, psk: bytes, peer_public: bytes) -> None:
    """Verifies the received HMAC against the expected value"""
    expected_hmac = hmac(psk, peer_public)
    if expected_hmac!= received_hmac:
        raise ValueError("HMAC verification failed")