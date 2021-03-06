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
__package__ = __name__

import authentication
import client
from client import create_connection, wrap_socket
import error
from lib import baseserver, conf
import packet
import server
from server import serve, SOCKS5Server

__doc__ = """
a pure-python SOCKS5 library

when executed, runs a configurable SOCKS server (version 5 by default)
"""

if __name__ == "__main__":
    config = conf.Conf()
    config.append(conf.Section())
    
    #mkconfig
    
    threaded = baseserver.threaded.Pipelining(nthreads = 1)
    serve(threaded, **config[0])
