import argparse
import json
from utilities.channel_setup import create_server_socket
from protocol.handshake import perform_handshake
from protocol.channel import run

def main() -> None:
    parser = argparse.ArgumentParser(description="SecureChannel server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--config", default="psk_config.json")
    parser.add_argument("--verbose", action="store_true", help="Show ciphertext/tag for each message")
    args = parser.parse_args()

    with open(args.config) as f:
        config = json.load(f)

    psk = config["psk"].encode()
    identity = "server"  

    sock = create_server_socket(args.host, args.port)
    key_c2s, key_s2c, nonce_material = perform_handshake(sock, psk, identity)
    print("[server] Handshake completed successfully.")
    run(sock, key_send=key_s2c, key_recv=key_c2s, nonce_material=nonce_material, identity=identity, verbose=args.verbose)

if __name__ == "__main__":
    main()
