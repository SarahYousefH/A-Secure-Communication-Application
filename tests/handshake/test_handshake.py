import socket
import threading
import pytest
from protocol.handshake import perform_handshake


def test_handshake_derives_matching_keys():
    """Client and server should derive identical session keys over a loopback socket."""
    psk = b"shared-secret-psk"
    client_sock, server_sock = socket.socketpair()

    results = {}

    def run_server():
        results["server"] = perform_handshake(server_sock, psk, "server")

    t = threading.Thread(target=run_server)
    t.start()
    client_keys = perform_handshake(client_sock, psk, "client")
    t.join()

    server_keys = results["server"]
    key_c2s_client, key_s2c_client, nonce_client = client_keys
    key_c2s_server, key_s2c_server, nonce_server = server_keys

    assert key_c2s_client == key_c2s_server
    assert key_s2c_client == key_s2c_server
    assert nonce_client == nonce_server
    assert key_c2s_client != key_s2c_client  # directional keys must differ


def test_handshake_rejects_wrong_psk():
    """A peer with the wrong PSK must fail authentication, not silently succeed."""
    client_sock, server_sock = socket.socketpair()
    results = {}

    def run_server():
        try:
            perform_handshake(server_sock, b"server-psk", "server")
        except RuntimeError as e:
            results["server_error"] = e

    t = threading.Thread(target=run_server)
    t.start()
    with pytest.raises(RuntimeError):
        perform_handshake(client_sock, b"client-psk", "client")
    t.join()
