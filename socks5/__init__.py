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

from lib import baseserver, conf
import client, protocol, server
from client import create_connection, wrap_socket

__doc__ = """
SOCKS5

when executed, runs a configurable SOCKS soerver (version 5 by default)
"""

if __name__ == "__main__":
    config = conf.Conf(autosync = False)
    
    #mkconfig

    threaded = baseserver.threaded.Pipelining(nthreads = 1)
    server.serve(threaded, **config)
