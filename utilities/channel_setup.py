import socket

def create_server_socket(host: str, port: int) -> socket.socket:
    """Creates a TCP server socket, binds, listens, accepts one connection.

    Blocks until a client connects. Returns the connected socket.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"[server] Listening on {host}:{port} ...")
    conn, addr = server.accept()
    print(f"[server] Connection from {addr}")
    return conn

def create_client_socket(host: str, port: int) -> socket.socket:
    """Creates a TCP client socket and connects to host:port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[client] Connected to {host}:{port}")
    return sock
