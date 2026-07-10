import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(certfile="server.pem")

raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
raw_sock.bind(('127.0.0.1', 8443))
raw_sock.listen(5)
print("[*] TLS 1.3 listening on port 8443...")

while True:
    client_conn, addr = raw_sock.accept()
    try:
        with context.wrap_socket(client_conn, server_side=True) as tls_conn:
            data = tls_conn.recv(1024)
            if data:
                tls_conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nTLS 1.3 Match")
    except Exception as e:
        print(f"[-] Error: {e}")
