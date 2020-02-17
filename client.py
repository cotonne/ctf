import socket

# Simple IPv4 TCP client

HOST = '127.0.0.1'
PORT = 8000

# For IPv6, replace HOST by ::1 and AF_INET => AF_INET6
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'GET / HTTP/1.1\nHost: a.vhost\n\n')
    data = s.recv(1024)
    print('> ', repr(data))
    s.close()
