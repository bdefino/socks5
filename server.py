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
import header
import method
import pack

__doc__ = """a simple SOCKS5 server framework"""
########slim down code
######test everything
#######play with sleep values
########integrate CLI
#########integrate baseserver framework
############integrate handler-created servers with baseserver
##########finish UDPAssociateRequestHandler

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

def parse_sockaddr(sockaddr, af = None):
    """
    parse a socket address string

    for AF_INET, this is: DOMAIN:PORT

    for AF_INET6, this is: DOMAIN,PORT,FLOW INFO,SCOPE ID
    """
    if af == None:
        af = socket.AF_INET
        
        if ',' in sockaddr:
            af = socket.AF_INET6
    parsed = ()
    
    if af == socket.AF_INET:
        parsed = sockaddr.split(':', 1)
    elif af == socket.AF_INET6:
        parsed = sockaddr.split(',', 3)
    else:
        raise ValueError("unknown address family")
    
    try:
        for i in range(1, len(parsed)):
            parsed[i] = int(parsed[i])
    except (IndexError, ValueError):
        raise ValueError("invalid socket address string")
    return tuple(parsed)

def str_addr(addr, af = None):
    """
    convert an address to  string

    see parse_sockaddr for the formats
    """
    if af == None:
        if len(addr) == 2:
            af = socket.AF_INET
        elif len(addr) == 4:
            af = socket.AF_INET6
    
    if af == socket.AF_INET:
        if len(addr) == 2:
            return ':'.join((str(e) for e in addr[:2]))
        raise ValueError("invalid AF_INET address")
    elif af == socket.AF_INET6:
        if len(addr) == 4:
            return ','.join((str(e) for e in addr[:4]))
        raise ValueError("invalid AF_INET6 address")
    raise ValueError("unknown address family")

class BaseRequestHandler(baseserver.eventhandler.EventHandler):
    pass

class BaseTCPRequestHandler(BaseRequestHandler):
    def pipe_conn_with(self, other_conn):
        """pipe the event's connection with another connection"""
        _continue = True
        last = time.time()
        
        try:
            other_conn.settimeout(self.event.server.timeout)
            self.event.conn.settimeout(self.event.server.timeout)
        except socket.error:
            pass
        
        while _continue and self.event.server.alive.get():
            for a, b in ((other_conn, self.event.conn),
                    (self.event.conn, other_conn)):
                chunk = ""
                time.sleep(self.server.conn_sleep)
                
                try:
                    chunk = a.recv(self.event.server.tcp_buflen)
                    last = time.time()
                except socket.timeout:
                    if time.time() - last >= self.event.server.conn_inactive:
                        _continue = False
                        break
                except socket.error:
                    _continue = False
                    break

                while _continue and self.event.server.alive.get(): # lossless
                    try:
                        b.sendall(chunk)
                        break
                    except socket.timeout:
                        pass
                    except socket.error:
                        _continue = False

                if not _continue or not self.event.server.alive.get():
                    break

class BaseUDPRequestHandler(BaseRequestHandler):
    pass

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
    
    def __call__(self):
        conn_reply = header.TCPReplyHeader()
        server_reply = header.TCPReplyHeader()
        server_sock = None
        start = time.time()
        target_conn = None
        target_remote = None
        
        try:
            server_sock = socket.socket(self.event.server.af,
                socket.SOCK_STREAM)
            server_sock.bind((self.event.request_header.unpack_addr(), 0))
            server_sock.listen(1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            server_sock.settimeout(self.event.server.conn_inactive)
            server_reply.bnd_addr, server_reply.bnd_port \
                = server_sock.getsockname()
        except socket.error as e:
            server_reply.errno(e.args[0], bind = True)
        
        try:
            self.event.conn.settimeout(self.event.server.timeout)
            self.event.conn.sendall(str(server_reply))
            
            if server_reply.bnd_port: # accept the first connection
                try:
                    target_conn, target_remote = server_sock.accept()
                    conn_reply.bnd_addr, conn_reply.bnd_port \
                        = target_remote
                except socket.error as e:
                    conn_reply.errno(e.args[0], accept = True)

            if server_sock: # close the server ASAP
                server_sock.close()
            self.event.conn.sendall(str(conn_reply))
            
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
    
    def __call__(self):
        reply = header.TCPReplyHeader()
        target_conn = None

        try:
            target_conn = socket.create_connection((
                self.event.request_header.unpack_addr(),
                self.event.request_header.dst_port),
                self.event.server.conn_inactive)
            reply.bnd_addr, reply.bnd_port = target_conn.getsockname()
        except socket.error as e:
            reply.errno(e.args[0], connect = True)
        
        try:
            self.event.conn.settimeout(self.event.server.timeout)
            self.event.conn.sendall(str(reply))
            
            if target_conn:
                self.pipe_conn_with(target_conn)
        finally:
            if target_conn:
                target_conn.close()

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

class ServerError(errors.SOCKS5Error):
    pass

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
    """###############support fragmentation?
    
    def __call__(self):
        bound = False
        reply = header.TCPReplyHeader()
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
        method_query = method.MethodQuery()
        request_header = header.TCPRequestHeader()
        
        with self.server.print_lock:
            print "Handling connection from", baseserver.straddress.str_addr(
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
                    baseserver.straddress.str_addr(self.event.remote)
            self.event.conn.close()

class UDPDatagramHandler:
    def __call__(self):######################
        pass

class UDPRequestHandler(BaseUDPRequestHandler):
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
