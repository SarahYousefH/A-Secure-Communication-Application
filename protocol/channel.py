import socket
import threading
from primitives.aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt


def _send_loop(sock: socket.socket, key_send: bytes, nonce_material: bytes, identity: str) -> None:
    """Reads lines from stdin, encrypts each one, and sends it over sock.

    Runs forever until the user closes stdin (Ctrl+D) or the connection drops.

    Each message:
      1. Read a line from stdin
      2. Build header: { version, message_type, sender_id, sequence_number }
      3. nonce = nonce_material XOR sequence_number  (12 bytes, little-endian)
      4. ciphertext, tag = AEAD_encrypt(key_send, nonce, plaintext, aad=header)
      5. Send: [ header bytes ][ ciphertext ][ tag ]
    """
    raise NotImplementedError


def _recv_loop(sock: socket.socket, key_recv: bytes, nonce_material: bytes) -> None:
    """Reads encrypted messages from sock, decrypts each one, and prints to stdout.

    Runs forever until the connection closes or a message fails authentication.

    last_seen_seq_number starts at 0. Each incoming message must have a
    sequence_number strictly greater than last_seen_seq_number — otherwise
    it fails replay detection and must be rejected.

    Each message:
      1. Read and parse header (plaintext)
      2. if sequence_number <= last_seen_seq_number: reject (replay detection)
         else: last_seen_seq_number = sequence_number
      3. nonce = nonce_material XOR sequence_number  (12 bytes, little-endian)
      4. plaintext = AEAD_decrypt(key_recv, nonce, ciphertext, tag, aad=header)
         → raises ValueError if tag is invalid (tampered message)
      5. Print plaintext to stdout
    """
    last_seen_seq_number = 0  # replay detection: reject any seq <= this
    raise NotImplementedError


def run(sock: socket.socket, key_send: bytes, key_recv: bytes, nonce_material: bytes, identity: str) -> None:
    """Starts the secure messaging loop and blocks until the session ends.

    Why threads: _send_loop blocks waiting for the user to type. _recv_loop
    blocks waiting for data from the socket. If we ran them sequentially we
    could only do one at a time — we would miss incoming messages while the
    user is typing, and vice versa. Running each in its own thread lets both
    directions operate simultaneously without either one blocking the other.

    Thread 1 (_send_loop): stdin → encrypt → socket
    Thread 2 (_recv_loop): socket → decrypt → stdout

    .join() makes run() wait here until both threads finish (i.e. until the
    connection closes or an error occurs in either direction).
    """
    t_send = threading.Thread(target=_send_loop, args=(sock, key_send, nonce_material, identity))
    t_recv = threading.Thread(target=_recv_loop, args=(sock, key_recv, nonce_material))
    t_send.start()
    t_recv.start()
    t_send.join()
    t_recv.join()

def _build_nonce(nonce_material: bytes, sequence_number: int) -> bytes:
    seq = sequence_number.to_bytes(12, "little")

    return bytes(
        a ^ b
        for a, b in zip(nonce_material, seq)
    )
