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
import baseserver
import conf
import errors
import protocol

__doc__ = """a simple SOCKS5 server framework"""
########slim down code
######test everything
#######play with sleep values
########integrate CLI
############integrate handler-created servers with baseserver
##########finish UDPAssociateRequestHandler
###########improve security

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

class BaseRequestHandler(baseserver.eventhandler.EventHandler):
    pass

class BindRequestHandler(BaseRequestHandler):
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
        BaseRequestHandler.__init__(self, *args, **kwargs)
        self.conn_reply = protocol.header.TCPReplyHeader()
        self.event.conn.settimeout(self.event.server.timeout)
        self.iteration = 0
        self.pipe_handler = None
        self.server_reply = protocol.header.TCPReplyHeader()
        self.server_sock = None
        self.start = time.time()
        self.target_conn = None
        self.target_remote = None
    
    def accept_first(self):
        try:
            self.server_sock = socket.socket(self.event.server.af,
                socket.SOCK_STREAM)
            self.server_sock.bind((self.event.request_header.unpack_addr(), 0))
            self.server_sock.listen(1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                1)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT,
                1)
            self.server_sock.settimeout(self.event.server.conn_inactive)
            self.server_reply.bnd_addr, self.server_reply.bnd_port \
                = self.server_sock.getsockname()
            
            self.event.conn.settimeout(self.event.server.timeout)
            self.event.conn.sendall(str(self.server_reply))
        except socket.error as e:
            self.server_reply.errno(e.args[0], bind = True)
            raise StopIteration()

        try:
            try:
                self.target_conn, self.target_remote \
                    = self.server_sock.accept()
                self.conn_reply.bnd_addr, self.conn_reply.bnd_port \
                    = self.target_remote
                self.pipe_handler = PipeHandler(PipeEvent(self.event.conn,
                    self.target_conn, self.event.server))
            except socket.error as e:
                self.conn_reply.errno(e.args[0], accept = True)

            try:
                self.event.conn.sendall(str(self.conn_reply))
            except socket.error:
                if self.target_conn:
                    target_conn.close()
                raise StopIteration()
        finally:
            self.server_sock.close()
            
            if not self.target_conn:
                raise StopIteration()
    
    def next(self):
        self.iteration += 1

        if self.iteration:
            return self.pipe()
        return self.accept_first()
    
    def pipe(self):
        try:
            self.pipe_handler.next()
        except StopIteration:
            if self.target_conn:
                self.target_conn.close()
            raise StopIteration()

class ConnectRequestHandler(BaseRequestHandler):
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
        BaseRequestHandler.__init__(self, event)
        self.iteration = 0
        self.reply = protocol.header.TCPReplyHeader()
        self.target_conn = None
    
    def connect(self):
        try:
            self.target_conn = socket.create_connection((
                self.event.request_header.unpack_addr(),
                self.event.request_header.dst_port),
                self.event.server.conn_inactive)
            self.pipe_handler = PipeHandler(PipeEvent(self.event.conn,
                target_conn, self.event.server))
            self.reply.bnd_addr, self.reply.bnd_port \
                = self.target_conn.getsockname()
        except socket.error as e:
            reply.errno(e.args[0], connect = True)
        
        try:
            self.event.conn.settimeout(self.event.server.timeout)
            self.event.conn.sendall(str(self.reply))
        except socket.error:
            raise StopIteration()

    def next(self):
        self.iteration += 1
        
        if self.iteration:
            return self.pipe()
        return self.connect()

    def pipe(self):
        try:
            self.pipe_handler.next()
        except StopIteration:
            if self.target_conn:
                self.target_conn.close()
            raise StopIteration()

class PipeEvent(baseserver.events.ServerEvent):
    def __init__(self, a, b, server):
        baseserver.events.ServerEvent.__init__(self, server)
        self.a = a
        self.b = b

class PipeHandler(baseserver.eventhandler.EventHandler):
    """bidirectional socket relay"""
    
    def __init__(self, event):
        baseserver.eventhandler.EventHandler.__init__(self, event)

        for s in (self.event.a, self.event.b):
            s.settimeout(self.event.server.timeout)
        self.last = None
    
    def next(self):
        if not self.last: # prep for inactivity timeout
            self.last = time.time()
        
        if self.event.server.alive.get():
            for a, b in ((self.event.a, self.event.b),
                    (self.event.b, self.event.a)):
                chunk = ""
                time.sleep(self.event.server.conn_sleep)
                
                try:
                    chunk = a.recv(self.event.server.tcp_buflen)
                    self.last = time.time()
                except socket.timeout:
                    if time.time() - self.last \
                            >= self.event.server.conn_inactive:
                        raise StopIteration()
                except socket.error:
                    raise StopIteration()

                # TCP is lossless
                
                while self.event.server.alive.get():
                    try:
                        b.sendall(chunk)
                        break
                    except socket.timeout:
                        pass
                    except socket.error:
                        raise StopIteration()

                if self.event.server.alive.get():
                    raise StopIteration()

class RequestEvent(baseserver.events.ServerEvent):
    def __init__(self, request_header, conn, remote, server):
        baseserver.events.ServerEvent.__init__(self, server)
        self.conn = conn
        self.remote = remote
        self.request_header = request_header

class Server(baseserver.server.BaseTCPServer):
    def __init__(self, event_class = baseserver.events.ConnectionEvent,
            event_handler_class = baseserver.eventhandler.ConnectionHandler,
            address = None, backlog = 100, buflen = 65536,
            conn_inactive = None, conn_sleep = 0.001, name = "SOCKS5",
            nthreads = -1, timeout = 0.001):
        baseserver.server.BaseTCPServer.__init__(self,
            baseserver.events.ConnectionEvent, TCPConnectionHandler,
            address, backlog, buflen, conn_inactive, conn_sleep, name,
            nthreads, timeout)

class IterativeServer(Server, baseserver.server.threaded.Iterative):
    def __init__(self, *args, **kwargs):
        Server.__init__(self, *args, **kwargs)
        baseserver.server.threaded.__init__(self, self.nthreads)

class ServerError(errors.SOCKS5Error):
    pass

class UDPAssociateRequestHandler(BaseRequestHandler):
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
    """###############support fragmentation?
    ###################integrate steppability
    
    def __call__(self):
        bound = False
        reply = protocol.header.TCPReplyHeader()
        server_sock = None
        target_address = (self.event.request_header.unpack_addr(),
            self.event.request_header.dst_port)
        
        try:
            server_sock = socket.socket(self.event.server.af,
                socket.SOCK_DGRAM)
            server_sock.bind((self.event.request_header.unpack_addr(), 0))
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            server_sock.settimeout(self.event.server.conn_inactive)
            reply.bnd_addr, reply.bnd_port = server_sock.getpeername()
        except socket.error as e:
            reply.errno(e.args[0], bind = True)
        
        try:
            self.conn.settimeout(self.event.server.timeout)
            self.conn.sendall(str(reply))
            
            if reply.bnd_port:
                while 1:
                    try:
                        self.conn.recv(0)
                    except socket.timeout:
                        pass
                    except socket.error:
                        break
                    
                    try:###################needs to handle datagram requests
                        datagram, remote = server_sock.recvfrom(
                            self.event.server.udp_buflen)
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

class TCPConnectionHandler(baseserver.eventhandler.ConnectionHandler):
    CMD_TO_HANDLER = {1: ConnectRequestHandler, 2: BindRequestHandler,
        3: UDPAssociateRequestHandler}
    
    def __call__(self):
        fp = self.event.conn.makefile()
        request_header = protocol.header.TCPRequestHeader()
        
        with self.server.print_lock:
            print "Handling connection from", baseserver.straddress.straddress(
                self.event.remote)
        
        try:
            wrapped_conn = auth.Auth(self.event.conn)()

            if wrapped_conn: # authenticated/authorized
                self.event.conn = wrapped_conn
                request_header.fload(self.event.conn.makefile())
                
                TCPConnectionHandler.CMD_TO_HANDLER[request_header.cmd](
                    RequestEvent(request_header, self.event.conn,
                        self.event.remote, self.event.server))()
        except KeyError: # command not supported
            try:
                self.event.conn.sendall(str(header.ReplyHeader(rep = 7)))
            except socket.error:
                pass
        except Exception as e:
            with self.event.server.print_lock:
                print >> sys.stderr, traceback.format_exc()
        finally:
            with self.event.server.print_lock:
                print "Closing connection with", \
                    baseserver.straddress.straddress(self.event.remote)
            self.event.conn.close()

class UDPDatagramHandler:
    def __call__(self):######################
        pass

class UDPRequestHandler(BaseRequestHandler):
    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    config = conf.Conf(autosync = False)
    
    #mkconfig
    
    if not set(config.keys()).issubset(set(("address", "backlog",
            "conn_inactive", "conn_sleep", "nthreads", "tcp_buflen", "timeout",
            "udp_buflen"))):##############gross
        raise KeyError("detected invalid keys")
    Server(**config)()
