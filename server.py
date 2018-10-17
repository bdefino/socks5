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
import time
import traceback

import header
import method
import pack
import threaded

__doc__ = """
a simple SOCKS5 server framework

doesn't support authentication
"""

def server_factory(protocol = socket.getprotobyname("tcp"), *args, **kwargs):
    """factory function for a protocol-specific SOCKS5 server"""
    return {socket.getprotobyname("tcp"): TCPServer,
        socket.getprotobyname("udp"): UDPServer}[protocol](*args, **kwargs)

class BaseServerSpawnedEventHandler:
    """
    allows an event handler to access the server
    that (in)directly spawned it
    """
    
    def __init__(self, event, server):
        self.event = event
        self.server = server

    def __call__(self):
        raise NotImplementedError()

class BaseRequestHandler(BaseServerSpawnedEventHandler):
    def __init__(self, request_header, *args, **kwargs):
        BaseServerSpawnedEventHandler.__init__(self, *args, **kwargs)
        self.request_header = request_header

class BaseTCPRequestHandler(BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseRequestHandler.__init__(self, *args, **kwargs)
        self.conn, self.remote = self.event

    def pipe_conn_with(self, other_conn):
        """pipe the connection with another connection"""
        _continue = True
        last = time.time()
        other_conn.settimeout(self.server.timeout)
        self.conn.settimeout(self.server.timeout)
        
        while self.server.alive and _continue:
            for a, b in ((other_conn, self.conn), (self.conn, other_conn)):
                chunk = ""
                time.sleep(self.server.conn_sleep)
                
                try:
                    chunk = a.recv(self.server.buflen)
                    last = time.time()
                except socket.timeout:
                    if time.time() - last >= self.server.conn_inactive:
                        _continue = False
                        break
                except socket.error:
                    _continue = False
                    break

                while 1: # TCP is lossless
                    try:
                        b.sendall(chunk)
                        break
                    except socket.timeout:
                        pass
                    except socket.error:
                        _continue = False
                        break

                if not _continue:
                    break

class BaseUDPRequestHandler(BaseRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseRequestHandler.__init__(self, *args, **kwargs)
        self.datagram, self.remote = self.event

class BindRequestHandler(BaseTCPRequestHandler):
    """
    The BIND request is used in protocols which require the client to
    accept connections from the server.  FTP is a well-known example,
    which uses the primary client-to-server connection for commands and
    status reports, but may use a server-to-client connection for
    transferring data on demand (e.g. LS, GET, PUT).

    It is expected that the client side of an application protocol will
    use the BIND request only to establish secondary connections after a
    primary connection is established using CONNECT.  In is expected that
    a SOCKS server will use DST.ADDR and DST.PORT in evaluating the BIND
    request.

    Two replies are sent from the SOCKS server to the client during a
    BIND operation.  The first is sent after the server creates and binds
    a new socket.  The BND.PORT field contains the port number that the
    SOCKS server assigned to listen for an incoming connection.  The
    BND.ADDR field contains the associated IP address.  The client will
    typically use these pieces of information to notify (via the primary
    or control connection) the application server of the rendezvous
    address.  The second reply occurs only after the anticipated incoming
    connection succeeds or fails.

    In the second reply, the BND.PORT and BND.ADDR fields contain the
    address and port number of the connecting host.
    """
    
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):
        bound = False
        conn_reply = header.ReplyHeader()
        _continue = True
        last = time.time()
        server_reply = header.ReplyHeader()
        server_sock = None
        target_conn = None
        target_remote = None

        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind((self.request.unpack_addr(), 0))
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            server_sock.settimeout(self.server.timeout)
            bound = True
        except socket.error as e:
            server_reply.errno(e.args[0])

        if bound:
            server_reply._addr, server_reply._port = server_sock.getsockname()
        self.conn.sendall(str(server_reply))

        if bound:
            server_sock.listen(1)
            
            while self.server.alive and not target_conn: # accept 1 connection
                try:
                    target_conn, target_remote = server_sock.accept()
                except socket.timeout:
                    if time.time() - last >= self.server.conn_inactive:
                        conn_reply.rep = 6
                        break
                except socket.error as e:
                    conn_reply.errno(e.args[0])
                    break
        
        if server_sock:
            server_sock.close()
        
        if target_conn:
            conn_reply.bnd_addr, conn_reply.bnd_port = target_remote

        try:
            self.conn.sendall(str(conn_reply))

            if target_conn:
                self.pipe_conn_with(target_conn)
        finally:
            if target_conn:
                target_conn.close()

class ConnectRequestHandler(BaseTCPRequestHandler):
    """
    In the reply to a CONNECT, BND.PORT contains the port number that the
    server assigned to connect to the target host, while BND.ADDR
    contains the associated IP address.  The supplied BND.ADDR is often
    different from the IP address that the client uses to reach the SOCKS
    server, since such servers are often multi-homed.  It is expected
    that the SOCKS server will use DST.ADDR and DST.PORT, and the
    client-side source address and port in evaluating the CONNECT
    request.
    """
    
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):
        _continue = True
        last = time.time()
        reply = header.ReplyHeader()
        target_conn = None

        try:
            target_conn = socket.create_connection((
                self.request_header.unpack_addr(),
                self.request_header.dst_port), self.server.conn_inactive)
        except socket.error as e:
            reply.errno(e.args[0])

        if target_conn:
            reply.bnd_addr, reply.bnd_port = target_conn.getsockname()
        
        try:
            self.conn.sendall(str(reply))
            
            if target_conn:
                self.pipe_conn_with(target_conn)
        finally:
            if target_conn:
                target_conn.close()

class DEFAULT:
    """global default values (optimized for speed)"""
    
    ADDRESS = ("", 1080)
    BACKLOG = 1000
    CONN_SLEEP = 0.001
    CONN_INACTIVE = 10
    NTHREADS = -1
    TCP_BUFLEN = 65536
    TIMEOUT = 0.001
    UDP_BUFLEN = 512

class Server(threaded.Threaded):
    """base class for an interruptible server (not exclusively for SOCKS5)"""
    
    def __init__(self, event_handler_class, socket_event_function,
            socket_type, address = DEFAULT.ADDRESS, backlog = DEFAULT.BACKLOG,
            buflen = DEFAULT.UDP_BUFLEN, conn_inactive = DEFAULT.CONN_INACTIVE,
            conn_sleep = DEFAULT.CONN_SLEEP, nthreads = DEFAULT.NTHREADS,
            timeout = DEFAULT.TIMEOUT):
        threaded.Threaded.__init__(self, nthreads)
        self.address = address
        self.alive = False
        self.backlog = backlog
        self.buflen = buflen
        self.conn_inactive = conn_inactive # inactivity threshold
        self.conn_sleep = conn_sleep
        self.event_handler_class = event_handler_class
        self.print_lock = thread.allocate_lock() # synchronize printing
        self.sleep = 1.0 / self.backlog # optimal value
        self._sock = socket.socket(socket.AF_INET, socket_type)
        self._sock.bind(self.address)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.settimeout(timeout)
        self.socket_event_function = socket_event_function
        self.socket_type = socket_type
        self.timeout = timeout

    def __call__(self):
        self.alive = True
        
        with self.print_lock:
            print "Serving SOCKS5 requests on %s:%u" % self.address
        
        try:
            while 1:
                try:
                    self.allocate_thread(self.event_handler_class(
                        self.socket_event_function(self._sock), self).__call__)
                except socket.error:
                    pass
                time.sleep(self.sleep)
        except KeyboardInterrupt:
            self.alive = False
        finally:
            with self.print_lock:
                print "Shutting down SOCKS5 server..."
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()

class TCPConnectionHandler(BaseServerSpawnedEventHandler):
    CMD_TO_HANDLER = {1: ConnectRequestHandler,
        }#2: BindRequestHandler, 3: UDPAssociateRequestHandler}
    
    def __init__(self, *args, **kwargs):
        BaseServerSpawnedEventHandler.__init__(self, *args, **kwargs)
        self.conn, self.remote = self.event

    def __call__(self):
        fp = self.conn.makefile()
        method_query = method.MethodQuery()
        request_header = header.RequestHeader()
        
        with self.server.print_lock:
            print "Handling connection from %s:%u" % self.remote
        
        try:
            method_query.fload(fp)
            self.conn.sendall(str(method.MethodResponse())) # no authentication
            request_header.fload(fp)
            
            TCPConnectionHandler.CMD_TO_HANDLER[request_header.cmd](
                request_header, self.event, self.server)()
        except KeyError: # command not supported
            try:
                self.conn.sendall(str(header.ReplyHeader(rep = 7)))
            except socket.error:
                pass
        except socket.error:
            pass
        except Exception as e:
            with self.server.print_lock:
                print >> sys.stderr, traceback.format_exc()
        finally:
            with self.server.print_lock:
                print "Closing connection with %s:%u" % self.remote
            self.conn.close()

class TCPServer(Server):
    def __init__(self, address = DEFAULT.ADDRESS, backlog = DEFAULT.BACKLOG,
            buflen = DEFAULT.TCP_BUFLEN, conn_inactive = DEFAULT.CONN_INACTIVE,
            conn_sleep = DEFAULT.CONN_SLEEP, nthreads = DEFAULT.NTHREADS,
            timeout = DEFAULT.TIMEOUT):
        Server.__init__(self, TCPConnectionHandler, lambda s: s.accept(),
            socket.SOCK_STREAM, address, backlog, buflen, conn_inactive,
            conn_sleep, nthreads, timeout)

    def __call__(self):
        self._sock.listen(self.backlog)
        Server.__call__(self)

class UDPServer(Server):
    def __init__(self, address = DEFAULT.ADDRESS, backlog = DEFAULT.BACKLOG,
            buflen = DEFAULT.UDP_BUFLEN, conn_inactive = DEFAULT.CONN_INACTIVE,
            conn_sleep = DEFAULT.CONN_SLEEP, nthreads = DEFAULT.NTHREADS,
            timeout = DEFAULT.TIMEOUT):
        Server.__init__(self, UDPDatagramHandler, lambda s: s.recvfrom(buflen),
            socket.SOCK_DGRAM, address, backlog, buflen, conn_inactive,
            conn_sleep, nthreads, timeout)

class UDPAssociateRequestHandler(BaseTCPRequestHandler):
    """
    The UDP ASSOCIATE request is used to establish an association within
    the UDP relay process to handle UDP datagrams.  The DST.ADDR and
    DST.PORT fields contain the address and port that the client expects
    to use to send UDP datagrams on for the association.  The server MAY
    use this information to limit access to the association.  If the
    client is not in possesion of the information at the time of the UDP
    ASSOCIATE, the client MUST use a port number and address of all
    zeros.

    A UDP association terminates when the TCP connection that the UDP
    ASSOCIATE request arrived on terminates.

    In the reply to a UDP ASSOCIATE request, the BND.PORT and BND.ADDR
    fields indicate the port number/address where the client MUST send
    UDP request messages to be relayed.
    """
    
    def __init__(self, *args, **kwargs):
        BaseTCPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):############################
        raise NotImplementedError()

class UDPDatagramHandler:
    def __init__(self, *args, **kwargs):
        BaseServerSpawnedEventHandler.__init__(self, *args, **kwargs)
        self.datagram, self.remote = self.event

class UDPRequestHandler(BaseUDPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseUDPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    address = DEFAULT.ADDRESS
    backlog = DEFAULT.BACKLOG
    buflen = DEFAULT.TCP_BUFLEN
    conn_inactive = DEFAULT.CONN_INACTIVE
    conn_sleep = DEFAULT.CONN_SLEEP
    nthreads = DEFAULT.NTHREADS
    timeout = DEFAULT.TIMEOUT
    TCPServer(address, backlog, buflen, conn_inactive, conn_sleep, nthreads,
        timeout)()
