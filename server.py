import socket
import asyncore
import asynchat
import socket
from hexdump import hexdump

# From https://docs.python.org/2/library/asynchat.html#asynchat-example

class Handler(asynchat.async_chat):

    def __init__(self, sock):
        asynchat.async_chat.__init__(self, sock=sock)
        self.ibuffer = []
        self.obuffer = ""
        self.set_terminator(b"\r\n\r\n")
        self.reading_headers = True
        self.handling = False
        self.cgi_data = None

    def collect_incoming_data(self, data):
        """Buffer the data"""
        hexdump(data)
        self.ibuffer.append(data)

    def found_terminator(self):
        """ Simple state machine """
        print("New terminator found")
        if self.reading_headers:
            self.reading_headers = False
            self.parse_headers(b"".join(self.ibuffer))
            self.ibuffer = []
            if self.op.upper() == b"POST":
                clen = self.headers.getheader("content-length")
                self.set_terminator(int(clen))
            else:
                self.handling = True
                self.set_terminator(None)
                self.handle_request()
        elif not self.handling:
            self.set_terminator(None)  # browsers sometimes over-send
            self.cgi_data = parse(self.headers, b"".join(self.ibuffer))
            self.handling = True
            self.ibuffer = []

    def parse_headers(self, headers):
        self.op = "GET"

    def handle_request(self):
        self.push(b'HTTP/1.0 200 OK\n\nOK!')
        self.close_when_done()

class Server(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.set_reuse_addr()        
        self.bind((host, port))
        self.listen(1)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, address = pair
            print('[+] New connection from [{0}]:{1}'.format(address[0], address[1]))
            Handler(sock)


if __name__ == '__main__':
    Server('::1', 8000)
    asyncore.loop()
