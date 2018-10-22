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

import auth
import errors
import header

__doc__ = "a simple SOCKS5 client"

def create_connection(*args, **kwargs):
    """create a SOCKS5 connection"""
    return wrap(socket.create_connection(*args, **kwargs))

def wrap(sock):#########################
    """wrap a socket with SOCKS5"""
    pass

class Client(socket.socket):
    def __init__(self, *args, **kwargs):
        socket.socket.__init__(self, *args, **kwargs)

    def connect(self, address, request_header = None, complain = True):
        """
        establish a SOCKS5 control connection,
        and return the ResponseHeader or optionally complain
        """
        socket.socket.connect(self, address)

        if not request_header:
            request_header = header.RequestHeader()
        self.sendall(str(request_header))
        
        try:
            response_header = self.recv(len(request_header))
        except socket.error as e:
            self.close()

            if complain:
                raise ClientError(*e.args)
        return response_header

class ClientError(errors.SOCKS5Error):
    pass
