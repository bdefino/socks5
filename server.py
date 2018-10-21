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

import auth
import conf
import header
import method
import pack
import threaded

__doc__ = """a simple SOCKS5 server framework"""
########move from thread spawning to task iteration
########slim down code
######test everything
#######play with sleep values

global DEFAULT_CONFIG
DEFAULT_CONFIG = conf.Conf(autosync = False)

for k, v in {"address": ("", 1080), "backlog": 1000, "conn_sleep": 0.001,
        "conn_inactive": 300, "nthreads": -1, "tcp_buflen": 65536,
        "timeout": 0.001, "udp_buflen": 512}.items():
    DEFAULT_CONFIG[k] = v

def open_config(path):
    """
    factory function for a server configuration file
    
    this turns off autosync and fills in missing configuration values
    """
    config = conf.Conf(path, autosync = False)

    for k, v in DEFAULT_CONFIG.items():
        if not k in config:
            config[k] = v
    return config

def server_factory(proto_name, *args, **kwargs):
    """factory function for a protocol-specific SOCKS5 server"""
    return {"tcp": TCPServer, "udp": UDPServer}[protocol.strip().lower()](
        *args, **kwargs)

class BaseServer(threaded.Threaded):
    """
    base class for an interruptible server (not exclusively for SOCKS5)
    
    config is a dict-like object
    """
    
    def __init__(self, event_handler_class, socket_event_function,
            socket_type, config = DEFAULT_CONFIG):
        threaded.Threaded.__init__(self)

        for k in ("address", "backlog", "buflen", "conn_inactive",
                "conn_sleep", "nthreads", "timeout"):
            setattr(self, k, config[k])
        self.alive = False
        self.event_handler_class = event_handler_class
        self.print_lock = thread.allocate_lock() # synchronize printing
        self.sleep = 1.0 / self.backlog # optimal value
        self._sock = socket.socket(socket.AF_INET, socket_type)
        self._sock.bind(self.address)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.settimeout(self.timeout)
        self.socket_event_function = socket_event_function
        self.socket_type = socket_type

    def __call__(self):
        self.alive = True
        
        with self.print_lock:
            print "Started server on %s:%u" % self.address
        
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
                print "Shutting down server..."
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()

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

        try:
            other_conn.settimeout(self.server.timeout)
            self.conn.settimeout(self.server.timeout)
        except socket.error:
            pass
        
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
        conn_reply = header.TCPReplyHeader()
        server_reply = header.TCPReplyHeader()
        server_sock = None
        start = time.time()
        target_conn = None
        target_remote = None
        
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind((self.request.unpack_addr(), 0))
            server_sock.listen(1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            server_sock.settimeout(self.server.conn_inactive)
            server_reply.bnd_addr, server_reply.bnd_port \
                = server_sock.getsockname()
        except socket.error as e:
            server_reply.errno(e.args[0])
        
        try:
            self.conn.settimeout(self.server.timeout)
            self.conn.sendall(str(server_reply))
            
            if server_reply.bnd_port: # accept the first connection
                try:
                    target_conn, target_remote = server_sock.accept()
                    conn_reply.bnd_addr, conn_reply.bnd_port \
                        = target_remote
                except socket.error as e:
                    conn_reply.errno(e.args[0])

            if server_sock: # close the server ASAP
                server_sock.close()
            self.conn.sendall(str(conn_reply))
            
            if target_conn:
                self.pipe_conn_with(target_conn)
        finally:
            if server_sock:
                server_sock.close()
            
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
        reply = header.TCPReplyHeader()
        target_conn = None

        try:
            target_conn = socket.create_connection((
                self.request_header.unpack_addr(),
                self.request_header.dst_port), self.server.conn_inactive)
            reply.bnd_addr, reply.bnd_port = target_conn.getsockname()
        except socket.error as e:
            reply.errno(e.args[0])
        
        try:
            self.conn.settimeout(self.server.timeout)
            self.conn.sendall(str(reply))
            
            if target_conn:
                self.pipe_conn_with(target_conn)
        finally:
            if target_conn:
                target_conn.close()

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

    def __call__(self):
        bound = False
        reply = header.TCPReplyHeader()
        server_sock = None
        target_address = (request.unpack_addr(), request.dst_port)
        
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server_sock.bind((self.request.unpack_addr(), 0))
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            server_sock.settimeout(self.server.timeout)
            reply.bnd_addr, reply.bnd_port = server_sock.getpeername()
        except socket.error as e:
            reply.errno(e.args[0])
        
        try:
            self.conn.settimeout(self.server.timeout)
            self.conn.sendall(str(reply))

            if reply.bnd_port:
                while 1:
                    try:
                        self.conn.recv()
                    except socket.timeout:
                        pass
                    except socket.error:
                        break
                    
                    try:
                        datagram, remote = server_sock.recvfrom()
                    except socket.error:
                        continue
                    
                    if remote[0] == self.remote[0]: # filter datagrams
                        try:
                            server_sock.sendto(datagram, target_address)
                        except socket.error:
                            pass
        finally:
            if server_sock:
                server_sock.close()

class TCPConnectionHandler(BaseServerSpawnedEventHandler):
    CMD_TO_HANDLER = {1: ConnectRequestHandler, 2: BindRequestHandler,
        3: UDPAssociateRequestHandler}
    
    def __init__(self, *args, **kwargs):
        BaseServerSpawnedEventHandler.__init__(self, *args, **kwargs)
        self.conn, self.remote = self.event

    def __call__(self):
        fp = self.conn.makefile()
        method_query = method.MethodQuery()
        request_header = header.TCPRequestHeader()
        
        with self.server.print_lock:
            print "Handling connection from %s:%u" % self.remote
        
        try:
            wrapped_conn = auth.Auth(self.conn)()

            if wrapped_conn: # authenticated/authorized
                self.conn = wrapped_conn
                request_header.fload(self.conn.makefile())
                
                TCPConnectionHandler.CMD_TO_HANDLER[request_header.cmd](
                    request_header, self.event, self.server)()
        except KeyError: # command not supported
            try:
                self.conn.sendall(str(header.ReplyHeader(rep = 7)))
            except socket.error:
                pass
        except Exception as e:
            with self.server.print_lock:
                print >> sys.stderr, traceback.format_exc()
        finally:
            with self.server.print_lock:
                print "Closing connection with %s:%u" % self.remote
            self.conn.close()

class Server(BaseServer):
    def __init__(self, config = DEFAULT_CONFIG):
        if "tcp_buflen" in config:
            config["buflen"] = config["tcp_buflen"]
        BaseServer.__init__(self, TCPConnectionHandler, lambda s: s.accept(),
            socket.SOCK_STREAM, config)

    def __call__(self):
        self._sock.listen(self.backlog)
        BaseServer.__call__(self)

class UDPDatagramHandler:
    def __init__(self, *args, **kwargs):
        BaseServerSpawnedEventHandler.__init__(self, *args, **kwargs)
        self.datagram, self.remote = self.event

    def __call__(self):######################
        pass

class UDPRequestHandler(BaseUDPRequestHandler):
    def __init__(self, *args, **kwargs):
        BaseUDPRequestHandler.__init__(self, *args, **kwargs)

    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    config = conf.Conf(autosync = False)
    
    #mkconfig
    
    for k in DEFAULT_CONFIG.keys():
        config[k] = DEFAULT_CONFIG[k]
    Server(config)()
