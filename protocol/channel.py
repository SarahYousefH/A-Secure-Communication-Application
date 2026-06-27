"""
Secure messaging channel.

This module provides bidirectional encrypted communication using
ChaCha20-Poly1305. Each message carries a plaintext authenticated
header and an encrypted payload protected by AEAD.
"""
import os
import socket
import struct
import threading
from primitives.aead import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

# Protocol message types
CHAT_MESSAGE = 1
FILE_NAME = 2
FILE_CHUNK = 3
FILE_COMPLETE = 4

# Size of each transmitted file chunk (1 KB)
FILE_CHUNK_SIZE = 1024

def _send_packet(
    sock: socket.socket,
    key: bytes,
    nonce_material: bytes,
    sender_id: int,
    sequence_number: int,
    message_type: int,
    payload: bytes,
) -> None:
    """
    Encrypt and send one protocol packet.

    Packet format:

        Header (16 bytes)
        Ciphertext
        Authentication Tag (16 bytes)
    """

    protocol_version = 1
    reserved = 0

    nonce = _build_nonce(
        nonce_material,
        sequence_number
    )

    header = struct.pack(
        "<BBBBQI",
        protocol_version,
        message_type,
        sender_id,
        reserved,
        sequence_number,
        len(payload)
    )

    ciphertext, tag = chacha20_poly1305_encrypt(
        key,
        nonce,
        payload,
        header
    )

    sock.sendall(
        header +
        ciphertext +
        tag
    )

def _send_file(
    sock: socket.socket,
    key: bytes,
    nonce_material: bytes,
    sender_id: int,
    sequence_number: int,
    filename: str,
) -> int:
    """
    Sends a file using encrypted AEAD packets.

    Packet order:

        FILE_NAME
        FILE_CHUNK
        FILE_CHUNK
        ...
        FILE_COMPLETE

    Returns the next available sequence number.
    """

    if not os.path.isfile(filename):
        print(f"File '{filename}' does not exist.")
        return sequence_number

    # Send the filename first
    _send_packet(
        sock,
        key,
        nonce_material,
        sender_id,
        sequence_number,
        FILE_NAME,
        os.path.basename(filename).encode(),
    )

    sequence_number += 1

    with open(filename, "rb") as f:

        while True:

            chunk = f.read(FILE_CHUNK_SIZE)

            if not chunk:
                break

            _send_packet(
                sock,
                key,
                nonce_material,
                sender_id,
                sequence_number,
                FILE_CHUNK,
                chunk,
            )

            sequence_number += 1

    # Tell the receiver the transfer is finished
    _send_packet(
        sock,
        key,
        nonce_material,
        sender_id,
        sequence_number,
        FILE_COMPLETE,
        b"",
    )

    sequence_number += 1

    print(f"Sent file '{filename}'.")

    return sequence_number

def _send_loop(sock: socket.socket, key_send: bytes, nonce_material: bytes, identity: str) -> None:
    """Reads lines from stdin, encrypts each one, and sends it over sock.

    Runs forever until the user closes stdin (Ctrl+D) or the connection drops.

    Each message:
      1. Read a line from stdin
      2. Build header: { protocol_version, message_type, sender_id, sequence_number }
      3. nonce = nonce_material XOR sequence_number  (12 bytes, little-endian)
      4. ciphertext, tag = AEAD_encrypt(key_send, nonce, plaintext, aad=header)
      5. Send: [ header bytes ][ ciphertext ][ tag ]
    """

    # Every outgoing message needs a unique sequence number
    sequence_number = 1

    if identity not in ("client", "server"):
        raise ValueError("Identity must be 'client' or 'server'.")

    # Convert the sender identity into a single byte
    # client = 0, server = 1
    sender_id = 0 if identity == "client" else 1

    while True:
        try:
            plaintext = input()
            # User requested a file transfer
            if plaintext.startswith("/send "):

                filename = plaintext[6:].strip()

                try:
                    sequence_number = _send_file(
                        sock,
                        key_send,
                        nonce_material,
                        sender_id,
                        sequence_number,
                        filename,
                    )

                except OSError:
                    print("Connection closed.")
                    break

                # File already sent
                continue

        # exit cleanly when the user closes stdin
        except EOFError:
            break

        try:
            _send_packet(
                sock,
                key_send,
                nonce_material,
                sender_id,
                sequence_number,
                CHAT_MESSAGE,
                plaintext.encode()
            )
        except OSError:
            print("Connection closed.")
            break

        sequence_number += 1


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

    recv_loop()
    │
    ├── read 16-byte header
    ├── unpack header
    ├── replay detection
    ├── read ciphertext
    ├── read 16-byte tag
    ├── rebuild nonce
    ├── verify + decrypt
    └── print plaintext
    """
    # The sender always sends: 16-byte header, ciphertext, 16-byte tag
    # the first thing the receiver always expects is the fixed-size header

    last_seen_seq_number = 0

    # State used while receiving a file
    receiving_file = False
    current_filename = None
    current_file = None
    try:
        while True:
            # Read one complete header
            header = _recv_exact(sock, 16)

            # The header is transmitted in plaintext because it is needed
            # to reconstruct the nonce and authenticate the message

            # Connection closed
            if not header:
                break

            # Extract the header fields from the received packet
            (
                protocol_version,
                message_type,
                sender_id,
                reserved,
                sequence_number,
                plaintext_length,
            ) = struct.unpack("<BBBBQI", header)

            # Validate the header before processing the message
            if protocol_version != 1:
                raise ValueError("Unsupported protocol version.")

            if message_type not in (
                    CHAT_MESSAGE,
                    FILE_NAME,
                    FILE_CHUNK,
                    FILE_COMPLETE,
            ):
                raise ValueError("Unknown message type.")

            if reserved != 0:
                raise ValueError("Reserved field must be zero.")

            if sender_id not in (0, 1):
                raise ValueError("Invalid sender ID.")

            # Reject duplicate or out-of-order messages
            if sequence_number <= last_seen_seq_number:
                raise ValueError("Replay attack detected.")

            # Read the ciphertext
            ciphertext = _recv_exact(
                sock,
                plaintext_length
            )

            # Read the 16-byte Poly1305 authentication tag
            tag = _recv_exact(
                sock,
                16
            )

            # Reconstruct the nonce using the received sequence number
            nonce = _build_nonce(
                nonce_material,
                sequence_number
            )

            try:
                plaintext = chacha20_poly1305_decrypt(
                    key_recv,
                    nonce,
                    ciphertext,
                    tag,
                    header
                )
            except ValueError:
                print("Authentication failed. Message may have been tampered with.")
                break

            last_seen_seq_number = sequence_number

            if message_type == CHAT_MESSAGE:
                print(plaintext.decode())

            elif message_type == FILE_NAME:

                filename = plaintext.decode()

                current_filename = "received_" + filename

                current_file = open(current_filename, "wb")

                receiving_file = True

                print(f"Receiving file '{current_filename}'...")

            elif message_type == FILE_CHUNK:

                if not receiving_file or current_file is None:
                    raise ValueError("Received file chunk before filename.")

                current_file.write(plaintext)

            elif message_type == FILE_COMPLETE:

                if receiving_file and current_file is not None:
                    current_file.close()

                    print(f"Saved file as '{current_filename}'.")

                    current_file = None
                    current_filename = None
                    receiving_file = False
    except ConnectionError:
        print("Peer disconnected.")
    except ValueError as e:
        print(e)


def run(sock: socket.socket, key_send: bytes, key_recv: bytes, nonce_material: bytes, identity: str, verbose = False) -> None:
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
    if len(nonce_material) != 12:
        raise ValueError("Nonce material must be 12 bytes.")

    if len(key_send) != 32:
        raise ValueError("Invalid send key. Send key must be 32 bytes.")

    if len(key_recv) != 32:
        raise ValueError("Invalid receive key. Receive key must be 32 bytes.")

    t_send = threading.Thread(target=_send_loop, args=(sock, key_send, nonce_material, identity))
    t_recv = threading.Thread(target=_recv_loop, args=(sock, key_recv, nonce_material))
    t_send.start()
    t_recv.start()
    t_send.join()
    t_recv.join()

    sock.close()


def _build_nonce(nonce_material: bytes, sequence_number: int) -> bytes:
    """Construct a unique 96-bit nonce by XORing the initial nonce material
       with the message sequence number."""
    # Convert the sequence number to a 12-byte little-endian value
    seq = sequence_number.to_bytes(12, "little")

    # XOR the initial nonce material with the sequence number
    # This guarantees a different nonce for every message
    return bytes(
        a ^ b
        for a, b in zip(nonce_material, seq)
    )


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from the socket.

    TCP is a byte stream, so a single recv() call may return fewer
    than the requested number of bytes.
    """
    data = bytearray()

    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed.")
        data.extend(chunk)

    return bytes(data)
