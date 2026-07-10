import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

with socket.create_connection(('127.0.0.1', 8443)) as sock:
    with context.wrap_socket(sock, server_hostname='127.0.0.1') as tls_conn:
        tls_conn.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = tls_conn.recv(1024)
        print(f"[+] Response: {response.decode()}")
        print(f"[+] TLS version used: {tls_conn.version()}")
