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

import auth
import protocol

__doc__ = "a simple SOCKS5 client"

def create_connection(*args, **kwargs):
    """create a SOCKS5 connection"""
    return wrap(socket.create_connection(*args, **kwargs))

def wrap(sock):
    """wrap a socket with SOCKS5 (not actually wrapping)"""
    wrapped = Client()
    wrapped.close() # free up the unused socket
    wrapped._sock = sock._sock # share the resources

    for method in socket._delegate_methods:
        if not method in Client.__all__: # preserve SOCKS5 overrides
            setattr(wrapped, method, getattr(wrapped._sock, method))
    return wrapped

class Client(socket.socket):
    __all__ = ["__init__", "connect"]
    
    def __init__(self, *args, **kwargs):
        socket.socket.__init__(self, *args, **kwargs)

    def connect(self, address, request_header = None, complain = True):
        """
        establish a SOCKS5 control connection,
        and return the ResponseHeader or optionally complain
        """
        response_header = protocol.header.TCPResponseHeader()
        socket.socket.connect(self, address)

        if not request_header:
            request_header = protocol.header.TCPRequestHeader()
        self.sendall(str(request_header))
        
        try:
            response_header.fload(self)
        except (protocol.error.ProtocolError, socket.error) as e:
            self.close()

            if complain:
                raise e

            if isinstance(e, socket.timeout): # no complaint, but no response
                response_header = None
        return response_header

class ClientError(protocol.error.SOCKS5Error):
    pass
