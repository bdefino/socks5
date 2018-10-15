# Copyright (C) 2018 Bailey Defino
# <https://bdefino.github.io>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
__package__ = "socks5"

import socket
import sys
import thread

import pack

__doc__ = """
a simple RFC 1928-compliant SOCKS5 server

doesn't support authentication
"""

global PRINT_LOCK # global synchronization mechanism
PRINT_LOCK = thread.allocate_lock()

def server_factory(protocol = socket.getprotobyname("tcp"), *args, **kwargs):
    """factory function for a protocol-specific SOCKS5 server"""
    return {socket.getprotobyname("tcp"): TCPServer,
        socket.getprotobyname("udp"): UDPServer}[protocol](*args, **kwargs)

class BaseTCPRequestHandler:
    def __init__(self, conn, remote, request_header):
        self.conn = conn
        self.remote = remote
        self.request_header = request_header

    def __call__(self):
        raise NotImplementedError()

class BindRequestHandler(BaseTCPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):#########################
        raise NotImplementedError()

class ConnectRequestHandler(BaseTCPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):
        _continue = True
        target_conn = None

        try:
            target_conn = socket.create_connection((
                self.request_header.unpack_addr(),
                self.request_header.dst_port))
        except socket.error:
            pass

        if target_conn:
            self.conn.settimeout(0.1)
            target_conn.settimeout(0.1)

            while _continue:
                for a, b in ((self.conn, target_conn),
                        (target_conn, self.conn)): # pipe sockets together
                    try:
                        a.sendall(b.recv(4096))
                    except socket.timeout:
                        pass
                    except socket.error:
                        _continue = False
                        break
            target_conn.close()

class UDPAssociateRequestHandler(BaseTCPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):############################
        raise NotImplementedError()

class TCPConnectionHandler:
    CMD_TO_HANDLER = {1: ConnectRequestHandler, 2: BindRequestHandler,
        3: UDPAssociateRequestHandler}
    
    def __init__(self, conn, remote):
        self.conn = conn
        self.remote = remote

    def __call__(self):
        fp = self.conn.makefile()
        method_query = MethodQuery()
        request_header = RequestHeader()
        
        try:
            method_query.fload(fp)
            self.conn.sendall(str(MethodResponse())) # no authentication
            request_header.fload(fp)
            
            
            with PRINT_LOCK:
                print "Handling TCP request for %s:%u from %s:%u" % (
                    request_header.unpack_addr(), request_header.dst_port,
                    self.remote[0], self.remote[1])
            TCPRequestHandler.CMD_TO_HANDLER[request_header.cmd](self.conn,
                self.remote, request_header)()
        except Exception as e:
            with PRINT_LOCK:
                print >> sys.stderr, e

        with PRINT_LOCK:
            print "Closing TCP connection between %s:%u and %s:%u" % (
                    self.remote[0], self.remote[1],
                    request_header.unpack_addr(), request.dst_port)
        self.conn.close()

class TCPServer:
    def __init__(self, address = ('', 1080), backlog = 1, timeout = 0.1):
        self.address = address
        self.backlog = backlog
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(self.address)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.settimeout(timeout)
        self.timeout = timeout

    def serve_forever(self):
        self._sock.listen(self.backlog)

        with PRINT_LOCK:
            print "Serving  TCP requests on %s:%u" % self.address

        try:
            while 1:
                try:
                    thread.start_new_thread(TCPConnectionHandler(
                        *self._sock.accept()).__call__, ())
                except socket.error:
                    pass
        except KeyboardInterrupt:
            pass

        with PRINT_LOCK:
            print "Shutting down  TCP server..."
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()

class UDPRequestHandler:
    def __init__(self, datagram, remote):
        self.datagram = datagram
        self.remote = remote

    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    address = ('', 1080)
    backlog = 1
    timeout = 0.1
    TCPServer(address, backlog, timeout).serve_forever()
