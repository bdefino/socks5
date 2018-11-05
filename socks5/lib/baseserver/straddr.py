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

def parseaddr(url):
    """parse a socket address from a URL"""
    parsed = []
    url = url.strip()

    if not url:
        raise ValueError("Empty URL")
    parsed = url.rsplit(':', 1)

    if parsed[0].startswith('['): # AF_INET6
        parsed[0] = parsed[0][1:].rstrip(']')
        parsed += [0, 0]
    
    try:
        parsed[1] = int(parsed[1])
    except ValueError:
        raise ValueError("Invalid URL")
    return tuple(parsed)

def straddr(addr):
    """convert an address to a URL"""
    if len(addr) == 4:
        return "[%s]:%u" % tuple(addr[:2])
    return "%s:%u" % addr
