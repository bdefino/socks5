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

import addr
from addr import atos, best, stoa
import basehttpserver
from basehttpserver import BaseHTTPServer, GETHandler, HEADHandler, \
    http_bufsize, HTTPConnectionHandler, HTTPHeaders, HTTPRequest, \
    HTTPRequestEvent, HTTPRequestHandler
import baseserver
from baseserver import BaseServer, SocketConfig, TCPConfig, UDPConfig
import event
from event import Event, ConnectionEvent, DatagramEvent, Handler, \
    IterableHandler, ServerEvent
from lib import threaded

__doc__ = """
a simple event-based server framework

see BaseHTTPServer (basehttpserver.BaseHTTPServer)
for an example implementation
"""
