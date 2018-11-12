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

import authentication
import error
import packet

__doc__ = "a simple SOCKS5 client"

def create_connection(server_address, target_address, timeout = None,
        source_address = None, *args, **kwargs):
    """socket.create_connection analog (with IPv6 support)"""
    af = socket.AF_INET

    if len(server_address) == 4:
        af = socket.AF_INET6
    elif not len(server_address) == 2:
        raise ValueError("unknown address family")
    sock = socket.socket(af, socket.SOCK_STREAM)

    if source_address:
        sock.bind(source_address)
    sock.settimeout(timeout)
    sock.connect(server_address)
    return wrap_socket(sock, target_address, 1, *args, **kwargs)

def wrap_socket(sock, target_address, cmd = 1, *args, **kwargs):
    """wrap a socket with SOCKS5"""
    reply = packet.Reply()
    request = packet.Request(3, cmd, *target_address[:2])
    sock = authentication.wrap_socket(sock, *args, **kwargs)
    
    try:
        sock.sendall(str(request))
        reply.fload(sock.makefile())
    except IOError as e:
        raise error.SOCKS5Error(e)
    
    if reply.rep:
        raise error.ResponseError(reply.rep)
    return sock
