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

import header
import method
import pack

__doc__ = """
a simple SOCKS5 server framework

doesn't support authentication
"""

global PRINT_LOCK # global synchronization mechanism
PRINT_LOCK = thread.allocate_lock()

def server_factory(protocol = socket.getprotobyname("tcp"), *args, **kwargs):
    """factory function for a protocol-specific SOCKS5 server"""
    return {socket.getprotobyname("tcp"): TCPServer,
        socket.getprotobyname("udp"): UDPServer}[protocol](*args, **kwargs)

class BaseHandler:
    """allows a handler to access the server that (in)directly spawned it"""
    
    def __init__(self, server):
        self.server = server

    def __call__(self):
        raise NotImplementedError()

class BaseTCPRequestHandler(BaseHandler):
    def __init__(self, conn, remote, request_header, *args, **kwargs):
        BaseHandler.__init__(self, *args, **kwargs)
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
        reply = header.ReplyHeader()
        target_conn = None

        try:
            target_conn = socket.create_connection((
                self.request_header.unpack_addr(),
                self.request_header.dst_port))
        except socket.error as e:
            reply.errno(e.args[0]) # this works even for unidentified errors

        if target_conn:
            reply.bnd_addr, reply.bnd_port = target_conn.getsockname()
            reply.detect_atyp()
        self.conn.sendall(str(reply))

        if target_conn:
            self.conn.settimeout(0.1)
            target_conn.settimeout(0.1)
            
            while self.server.alive and _continue:
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

class TCPConnectionHandler(BaseHandler):
    CMD_TO_HANDLER = {1: ConnectRequestHandler, 2: BindRequestHandler,
        3: UDPAssociateRequestHandler}
    
    def __init__(self, conn, remote, *args, **kwargs):
        BaseHandler.__init__(self, *args, **kwargs)
        self.conn = conn
        self.remote = remote

    def __call__(self):
        fp = self.conn.makefile()
        method_query = method.MethodQuery()
        request_header = header.RequestHeader()
        
        try:
            method_query.fload(fp)
            self.conn.sendall(str(method.MethodResponse())) # no authentication
            request_header.fload(fp)
            
            
            with PRINT_LOCK:
                print "Handling TCP request for %s:%u from %s:%u" % (
                    request_header.unpack_addr(), request_header.dst_port,
                    self.remote[0], self.remote[1])
            TCPConnectionHandler.CMD_TO_HANDLER[request_header.cmd](self.conn,
                self.remote, request_header, self.server)()
        except IOError as e:
            with PRINT_LOCK:
                print >> sys.stderr, e

        with PRINT_LOCK:
            print "Closing TCP connection between %s:%u and %s:%u" % (
                    self.remote[0], self.remote[1],
                    request_header.unpack_addr(), request_header.dst_port)
        self.conn.close()

class Server:
    """base class for an interruptible server (not exclusively for SOCKS5)"""
    
    def __init__(self, event_handler_class, socket_event_function_name,
            socket_type, address = ('', 1080), timeout = 0.1):
        self.address = address
        self.alive = False
        self.event_handler_class = event_handler_class
        self._sock = socket.socket(socket.AF_INET, socket_type)
        self._sock.bind(self.address)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.settimeout(timeout)
        self.socket_event_function_name = socket_event_function_name
        self.socket_type = socket_type
        self.timeout = timeout

    def serve_forever(self):
        self.alive = True
        
        with PRINT_LOCK:
            print "Serving SOCKS5 requests on %s:%u" % self.address
        
        try:
            while 1:
                try:
                    thread.start_new_thread(self.event_handler_class(
                        *getattr(self._sock,
                        self.socket_event_function_name)(),
                        server = self).__call__, ())
                except socket.error:
                    pass
        except KeyboardInterrupt:
            self.alive = False

        with PRINT_LOCK:
            print "Shutting down SOCKS5 server..."
        self._sock.shutdown(socket.SHUT_RDWR)
        self._sock.close()

class TCPServer(Server):
    def __init__(self, address = ('', 1080), backlog = 1, timeout = 0.1):
        Server.__init__(self, TCPConnectionHandler, "accept",
            socket.SOCK_STREAM, address, timeout)
        self.backlog = backlog

    def serve_forever(self):
        self._sock.listen(self.backlog)
        Server.serve_forever(self)

class UDPRequestHandler(BaseHandler):
    def __init__(self, datagram, remote, *args, **kwargs):
        BaseHandler.__init__(self, *args, **kwargs)
        self.datagram = datagram
        self.remote = remote

    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    address = ('', 1080)
    backlog = 1
    timeout = 0.1
    TCPServer(address, backlog, timeout).serve_forever()
