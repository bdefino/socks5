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

from lib import baseserver
from lib import conf
import v4client
import v4error
import v4header
import v4method
import v4server
import v5auth
import v5client
import v5error
import v5header
import v5method
import v5server

__doc__ = """
SOCKS5 with backwards compatibility for SOCKS4

when executed, runs a configurable SOCKS server (version 5 by default)
"""

def create_connection(address, timeout = None, source_address = None,
        version = 5,):#########################################auth stuff
    """socket.create_connection analog"""
    pass###############################################

def SOCKSServerFactory(version = 5, *args, **kwargs):
    """return a version-specific server"""
    try:
        return {4: v4server.SOCKS4Server, 5: v5server.SOCKS5Server}[version](
            *args, **kwargs)
    except KeyError:
        raise ValueError("unsupported SOCKS version (%u)" % version)

def wrap_socket():
    pass#############################################

if __name__ == "__main__":
    config = conf.Conf(autosync = False)
    
    #mkconfig
    
    server = SOCKSServerFactory(5, address = ("::1", 1080, 0 , 0), **config)
    server.thread(baseserver.threaded.Pipelining(nthreads = 1))
    server()
