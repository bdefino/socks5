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
import errno
import socket

import error
import pack

__doc__ = "header formats"

def response_error_factory(rep):
    """return a ResponseError based on REP"""
    if rep in ResponseError.REP_TO_MSG:
        return ResponseError(ResponseError.REP_TO_MSG[c])
    return

class BaseHeader:
    """
    address manipulation faculties for headers

    shared between TCP and UDP
    """
    
    def __init__(self, addr = "", atyp = 3):
        self._addr = addr
        self.atyp = atyp

    def address_tuple(self):
        """return a usable address tuple"""
        af = self.determine_af()
        host = self.unpack_addr()

        if af == socket.AF_INET:
            return (host, self._port)
        return (host, self._port, 0, 0) # the latter two are indeterminate

    def determine_af(self):
        """determine the address family"""
        if self.atyp == 1:
            return socket.AF_INET
        elif self.atyp == 4:
            return socket.AF_INET6
        elif ':' in self._addr:
            return socket.AF_INET6
        return socket.AF_INET

    def unpack_addr(self):
        """return the IP address string or domain name in *.ADDR"""
        if self.atyp == 3:
            return self._addr
        return socket.inet_ntop(self.determine_af(), self._addr)

    def update_addrinfo(self):
        """set ATYP based on *.ADDR"""
        self.atyp = 3

        if not '.' in self._addr:
            self.atyp = 1

            if len(self._addr) == 8:
                self.atyp = 4

class BaseTCPHeader(BaseHeader):
    """
    the contents of addr, port, and special vary between a reply and request;
    their internal values (_addr, _port, and _special) should be managed by
    subclasses
    
    this class simply diminishes repeated code

    _addr should be a PACKED IP address OR a domain name
    """
    
    def __init__(self, addr = "", atyp = 3, port = 0, rsv = 0, special = 0,
            ver = 5):
        BaseHeader.__init__(self, addr, atyp)
        self._port = port
        self.rsv = rsv
        self._special = special
        self.ver = ver

    def fload(self, fp):
        """load from a file-like object"""
        self.ver = pack.unpack(fp.read(1))
        self._special = pack.unpack(fp.read(1))
        self.rsv = pack.unpack(fp.read(1))
        self.atyp = pack.unpack(fp.read(1))
        
        if self.atyp == 1:
            self._addr = fp.read(4)
        elif self.atyp == 3:
            self._addr = fp.read(pack.unpack(fp.read(1)))
        elif self.atyp == 4:
            self._addr = fp.read(16)
        self._port = pack.unpack(fp.read(2))

    def __str__(self):
        header = [pack.pack(self.ver, 1), pack.pack(self._special, 1),
            pack.pack(self.rsv, 1), pack.pack(self.atyp, 1)]
        self.update_addrinfo()

        if self.atyp == 3:
            for e in (pack.pack(len(self._addr), 1), self._addr):
                header.append(e)
        else:
            header.append(self._addr)
        header.append(pack.pack(self._port, 2))
        return "".join(header)

class BaseUDPHeader(BaseHeader):
    """
      +----+------+------+----------+----------+----------+
      |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
      +----+------+------+----------+----------+----------+
      | 2  |  1   |  1   | Variable |    2     | Variable |
      +----+------+------+----------+----------+----------+

     The fields in the UDP request header are:

          o  RSV  Reserved X'0000'
          o  FRAG    Current fragment number
          o  ATYP    address type of following addresses:
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT       desired destination port
          o  DATA     user data # NOT PART OF THE HEADER
    """
    
    def __init__(self, addr = "", atyp = 3, frag = 0, port = 0, rsv = 0):
        BaseHeader.__init__(self, addr, atyp)
        self.frag = frag
        self._port = port
        self.rsv = rsv

    def fload(self, fp):
        """load from a file-like object"""
        self.rsv = pack.unpack(fp.read(2))
        self.frag = pack.unpack(fp.read(1))
        self.atyp = pack.unpack(fp.read(1))

        if self.atyp == 1:
            self._addr = fp.read(4)
        elif self.atyp == 3:
            self._addr = fp.read(pack.unpack(fp.read(1)))
        elif self.atyp == 4:
            self._addr = fp.read(16)
        self._port = fp.read(2)

    def __str__(self):
        header = [pack.pack(self.rsv, 2), pack.pack(self.frag, 1),
            pack.pack(self.atyp, 1)]

        if self.atyp == 3:
            for e in (pack.pack(len(self._addr), 1), self._addr):
                header.append(e)
        else:
            header.append(self._addr)
        header.append(pack.pack(self._port, 2))
        return "".join(header)

class ResponseError(error.ProtocolError):
    REP_TO_MSG = {1: "general SOCKS server failure",
        2: "connection not allowed by ruleset", 3: "Network unreachable",
        4: "Host unreachable", 5: "Connection refused", 6: "TTL expired",
        7: "Command not supported", 8: "Address type not supported"}
    
    pass

class TCPReplyHeader(BaseTCPHeader):
    """
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  REP    Reply field:
             o  X'00' succeeded
             o  X'01' general SOCKS server failure
             o  X'02' connection not allowed by ruleset
             o  X'03' Network unreachable
             o  X'04' Host unreachable
             o  X'05' Connection refused
             o  X'06' TTL expired
             o  X'07' Command not supported
             o  X'08' Address type not supported
             o  X'09' to X'FF' unassigned
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  BND.ADDR       server bound address
          o  BND.PORT       server bound port in network octet order
    """
    ERRNO_TO_REP = {0: 0, errno.EAFNOSUPPORT: 8, errno.ECONNREFUSED: 5,
        errno.EHOSTUNREACH: 4, errno.ENETUNREACH: 3, errno.ETIMEDOUT: 6}
    
    def __init__(self, atyp = 3, bnd_addr = "", bnd_port = 0, rep = 0, rsv = 0,
            ver = 5):
        BaseTCPHeader.__init__(self, bnd_addr, atyp, bnd_port, rsv, rep, ver)
        self.bnd_addr = self._addr
        self.bnd_port = self._port
        self.rep = self._special

    def errno(self, e, accept = False, bind = False, connect = False):
        """
        set REP based on the error number and the operation

        only one operation (accept, bind, connect) may be set

        when an unknown error is present and connect evaluates to True,
        the error is identified as "connection not allowed by ruleset"
        
        otherwised, unknown errors are identified as
        "general SOCKS server failure"
        """
        if sum((1 for e in (accept, bind, connect) if e)) > 1:
            raise ValueError("multiple socket operations specified")
        self.rep = 1

        if connect:
            self.rep = 2
        
        if e in ReplyHeader.ERRNO_TO_REP:
            self.rep = ReplyHeader.ERRNO_TO_REP[e]
    
    def fload(self, fp):
        """load from a file-like object"""
        BaseTCPHeader.fload(self, fp)
        self.bnd_addr = self._addr
        self.bnd_port = self._port
        self.rep = self._special

    def __str__(self):
        self._special = self.rep
        self.update_addrinfo()
        return BaseTCPHeader.__str__(self)

    def unpack_addr(self):
        """return the IP address or domain name in BND.ADDR"""
        self._addr = self.bnd_addr
        self._port = self.bnd_port
        return BaseTCPHeader.unpack_addr(self)

    def update_addrinfo(self):
        """overwrite the underlying address info and detect ATYP"""
        self._addr = self.bnd_addr
        self._port = self.bnd_port
        BaseTCPHeader.update_addrinfo(self)

class TCPRequestHeader(BaseTCPHeader):
    """
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

     Where:

          o  VER    protocol version: X'05'
          o  CMD
             o  CONNECT X'01'
             o  BIND X'02'
             o  UDP ASSOCIATE X'03'
          o  RSV    RESERVED
          o  ATYP   address type of following address
             o  IP V4 address: X'01'
             o  DOMAINNAME: X'03'
             o  IP V6 address: X'04'
          o  DST.ADDR       desired destination address
          o  DST.PORT desired destination port in network octet
             order
    """
    
    def __init__(self, atyp = 3, cmd = 1, dst_addr = "", dst_port = 0, rsv = 0,
            ver = 5):
        BaseTCPHeader.__init__(self, dst_addr, atyp, dst_port, rsv, cmd, ver)
        self.cmd = self._special
        self.dst_addr = self._addr
        self.dst_port = self._port

    def fload(self, fp):
        """load from a file-like object"""
        BaseTCPHeader.fload(self, fp)
        self.cmd = self._special
        self.dst_addr = self._addr
        self.dst_port = self._port

    def __str__(self):
        self._special = self.cmd
        self.update_addrinfo()
        return BaseTCPHeader.__str__(self)

    def unpack_dst_addr(self):
        """return the IP address of domain name in DST.ADDR"""
        self._addr = self.dst_addr
        self._port = self.dst_port
        return BaseTCPHeader.unpack_addr(self)

    def update_addrinfo(self):
        """overwrite the underlying address info and detect ATYP"""
        self._addr = self.dst_addr
        self._port = self.dst_port
        BaseTCPHeader.update_addrinfo(self)

class UDPHeader(BaseUDPHeader):
    """alias for BaseUDPHeader"""
    
    def __init__(self, *args, **kwargs):
        BaseUDPHeader.__init__(self, *args, **kwargs)