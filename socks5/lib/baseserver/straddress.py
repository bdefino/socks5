# Copyright 2018 Bailey Defino
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
__package__ = __name__

import socket

__doc__ = "address strings"

def parseaddress(sockaddr, af = None):
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

def straddress(addr, af = None):
    """
    convert an address to  string

    see parse_sockaddr for the formats
    """
    if af == None:
        if len(addr) == 2:
            af = socket.AF_INET
        elif len(addr) == 4:
            af = socket.AF_INET6
    
    for known_af, length, sep in ((socket.AF_INET, 2, ':'),
            (socket.AF_INET6, 4, ',')):
        if af == known_af:
            if len(addr) == length:
                return sep.join((str(e) for e in addr))
            raise ValueError("invalid address length")
    raise ValueError("unknown address family")
