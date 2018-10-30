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
import socket
import sys
import thread
import time
import traceback

import auth
from lib import baseserver
from lib import conf
import protocol

__doc__ = """a simple SOCKS5 server framework"""
########slim down code
######test everything
#######play with sleep values
########integrate CLI
############integrate handler-created servers with baseserver?
##########finish UDPAssociateRequestHandler
###########improve security
##########make sure that all error chains give proper feedback

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
        self.pipe_handler = None
        self.server_reply = protocol.header.TCPReplyHeader()
        self.start = time.time()
        self.target_conn = None
        self.target_remote = None
    
    def accept_first(self):
        """accept the first connection on BND.*"""
        server_sock = None
        
        try:
            server_sock = socket.socket(self.event.server.af,
                socket.SOCK_STREAM)
            server_sock.bind((self.event.request_header.unpack_addr(), 0))
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            self.server_sock.settimeout(self.event.server.conn_inactive)
            self.server_reply.bnd_addr, self.server_reply.bnd_port \
                = server_sock.getsockname()
            server_sock.listen(1)
        except socket.error as e:
            self.server_reply.errno(e.args[0], bind = True)
            server_sock = None
        finally:
            try:
                self.event.conn.settimeout(self.event.server.timeout)
                self.event.conn.sendall(str(self.server_reply))
            except socket.error as e:
                if server_sock:
                    server_sock.close()
                    server_sock = None
        
        if not server_sock:
            raise StopIteration()
        
        try:
            self.target_conn, self.target_remote = server_sock.accept()
            self.conn_reply.bnd_addr, self.conn_reply.bnd_port \
                = self.target_remote
            self.pipe_handler = PipeHandler(PipeEvent(self.event.conn,
                self.target_conn, self.event.server))
        except socket.error as e:
            self.conn_reply.errno(e.args[0], accept = True)
        finally:
            try:
                self.event.conn.sendall(str(self.conn_reply))
            except socket.error:
                if self.target_conn:
                    selt.target_conn.close()
                    self.target_conn = None
            server_sock.close()
            
            if not self.target_conn:
                raise StopIteration()
    
    def next(self):
        if target_conn:
            return self.pipe()
        return self.accept_first()
    
    def pipe(self):
        """pipe the next chunk of data"""
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
        BaseRequestHandler.__init__(self, *args, **kwargs)
        self.pipe_sockets_handler = None
        self.reply = protocol.header.TCPReplyHeader()
        self.target_conn = None
    
    def connect(self):
        """attempt to connect to DST.*"""
        try:
            self.target_conn = socket.socket(
                self.event.request_header.determine_af(), socket.SOCK_STREAM)
            self.target_conn.settimeout(self.event.server.conn_inactive)
            self.target_conn.connect(self.event.request_header.address_tuple())
            
            self.pipe_sockets_handler = PipeSocketsHandler(PipeSocketsEvent(
                self.event.conn, self.target_conn, self.event.server))
            self.reply.bnd_addr, self.reply.bnd_port \
                = self.target_conn.getsockname()
        except socket.error as e:
            self.reply.errno(e.args[0], connect = True)
            self.target_conn.close()
            self.target_conn = None
        finally:
            try:
                self.event.conn.settimeout(self.event.server.timeout)
                self.event.conn.sendall(str(self.reply))
            except socket.error:
                if self.target_conn:
                    self.target_conn.close()
                    self.target_conn = None

            if not self.target_conn:
                raise StopIteration()

    def next(self):
        if self.target_conn:
            return self.pipe_sockets()
        return self.connect()

    def pipe_sockets(self):
        """pipe data between the client and the connection with DST.*"""
        try:
            self.pipe_sockets_handler.next()
        except StopIteration:
            if self.target_conn:
                self.target_conn.close()
            raise StopIteration()

class PipeSocketsEvent(baseserver.event.ServerEvent):
    def __init__(self, a, b, server):
        baseserver.event.ServerEvent.__init__(self, server)
        self.a = a
        self.b = b

class PipeSocketsHandler(baseserver.eventhandler.EventHandler):
    """bidirectional socket relay"""
    
    def __init__(self, event):
        baseserver.eventhandler.EventHandler.__init__(self, event)

        for s in (self.event.a, self.event.b):
            s.settimeout(self.event.server.timeout)
        self.last = time.time()
    
    def next(self):
        """pipe a chunk of data in one direction, then reverse the direction"""
        chunk = ""
        
        if not self.event.server.alive.get(): # check before
            raise StopIteration()
        
        try:
            chunk = self.event.a.recv(self.event.server.tcp_buflen)
            self.last = time.time()
        except socket.timeout:
            if not self.event.server.conn_inactive == None \
                    and time.time() - self.last \
                        >= self.event.server.conn_inactive:
                raise StopIteration()
        except socket.error:
            raise StopIteration()
        
        while self.event.server.alive.get(): # TCP is lossless
            try:
                self.event.b.sendall(chunk)
                break
            except socket.timeout:
                pass
            except socket.error:
                raise StopIteration()

        # change direction
        
        temp = self.event.a
        self.event.a = self.event.b
        self.event.b = temp

class RequestEvent(baseserver.event.ConnectionEvent):
    def __init__(self, request_header, *args, **kwargs):
        baseserver.event.ConnectionEvent.__init__(self, *args, **kwargs)
        self.request_header = request_header

class ServerError(protocol.error.SOCKS5Error):
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
    ##########near-complete rewrite
    
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
    
    def next(self):
        address_string = baseserver.straddr.straddr(self.event.remote)
        fp = self.event.conn.makefile()
        request_header = protocol.header.TCPRequestHeader()
        
        self.event.server.sprint("Handling connection with", address_string)
        
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
            self.event.server.sfprint(sys.stderr,
                "ERROR while handling connection with %s:\n" % address_string,
                traceback.format_exc())
        finally:
            self.event.server.sprint("Closing connection with", address_string)
            self.event.conn.close()
        raise StopIteration()

class IterativeServer(baseserver.server.BaseIterativeTCPServer):
    def __init__(self, address = baseserver.server.best_address(1080),
            backlog = 100, conn_inactive = None, conn_sleep = 0.001,
            event_class = baseserver.event.ConnectionEvent,
            event_handler_class = TCPConnectionHandler,
            name = "iterative SOCKS5", nthreads = -1, queue_output = False,
            tcp_buflen = 65536, timeout = 0.001, udp_buflen = 512):
        baseserver.server.BaseIterativeTCPServer.__init__(self, address,
            backlog, tcp_buflen, conn_inactive, conn_sleep, event_class,
            event_handler_class, name, nthreads, queue_output, timeout)
        self.tcp_buflen = tcp_buflen
        self.udp_buflen = udp_buflen

class PipeliningServer(baseserver.server.BasePipeliningTCPServer):
    def __init__(self, address = baseserver.server.best_address(1080),
            backlog = 100, conn_inactive = None, conn_sleep = 0.001,
            event_class = baseserver.event.ConnectionEvent,
            event_handler_class = TCPConnectionHandler,
            name = "pipelining SOCKS5", nthreads = -1, queue_output = False,
            tcp_buflen = 65536, timeout = 0.001, udp_buflen = 512):
        baseserver.server.BasePipeliningTCPServer.__init__(self, address,
            backlog, tcp_buflen, conn_inactive, conn_sleep, event_class,
            event_handler_class, name, nthreads, queue_output, timeout)
        self.tcp_buflen = tcp_buflen
        self.udp_buflen = udp_buflen

class Server(baseserver.server.BaseTCPServer):
    def __init__(self, address = baseserver.server.best_address(1080),
            backlog = 100, conn_inactive = None, conn_sleep = 0.001,
            event_class = baseserver.event.ConnectionEvent,
            event_handler_class = TCPConnectionHandler, name = "SOCKS5",
            tcp_buflen = 65536, timeout = 0.001, udp_buflen = 512):
        baseserver.server.BaseTCPServer.__init__(self, address, backlog,
            tcp_buflen, lambda e: e(), conn_inactive, conn_sleep, event_class,
            event_handler_class, name, timeout)
        self.tcp_buflen = tcp_buflen
        self.udp_buflen = udp_buflen

class ThreadedServer(baseserver.server.BaseThreadedTCPServer):
    def __init__(self, address = baseserver.server.best_address(1080),
            backlog = 100, conn_inactive = None, conn_sleep = 0.001,
            event_class = baseserver.event.ConnectionEvent,
            event_handler_class = TCPConnectionHandler,
            name = "threaded SOCKS5", nthreads = -1, queue_output = False,
            tcp_buflen = 65536, timeout = 0.001, udp_buflen = 512):
        baseserver.server.BaseThreadedTCPServer.__init__(self, address,
            backlog, tcp_buflen, conn_inactive, conn_sleep, event_class,
            event_handler_class, name, nthreads, queue_output, timeout)
        self.tcp_buflen = tcp_buflen
        self.udp_buflen = udp_buflen

class UDPDatagramHandler:
    def __call__(self):######################
        pass

class UDPRequestHandler(BaseRequestHandler):
    def __call__(self):###########################
        raise NotImplementedError()

if __name__ == "__main__":
    config = conf.Conf(autosync = False)
    
    #mkconfig
    
    IterativeServer(**config)()
