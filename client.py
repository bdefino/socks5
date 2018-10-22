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

def socket(address, *sock_args, **sock_kwargs):
    pass

def wrap(sock):
    pass

class Client(socket.socket):
    def __init__(self, *args, **kwargs):
        socket.socket.__init__(self, *args, **kwargs)

    def connect(self, address, request_header = None):
        socket.socket.connect(self, address)

        if not request_header:
            request_header = header.RequestHeader()
        self.sendall(str(request_header))

        try:
            response_header = self.recv(len(request_header))
        except socket.timeout:
            response_header = None
        except socket.error as e:
            self.close()
            raise e

        if response_header and response_header.rep:
            raise 

class ClientError(errors.BaseError):
    pass
