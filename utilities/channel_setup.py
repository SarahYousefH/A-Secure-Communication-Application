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

def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Reads exactly n bytes from sock, looping until all are received.

    TCP does not guarantee a single recv() call returns all requested
    bytes — it may return fewer. This loops until n bytes are collected.
    Raises ConnectionError if the peer closes the connection early.
    """
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed before all bytes were received")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)
