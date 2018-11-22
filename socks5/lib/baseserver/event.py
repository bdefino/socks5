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
import addr
from lib import threaded

__doc__ = "events"

global Handler # alias

class Event:
    def __init__(self):
        pass

    def __str__(self):
        return ""

class IterableHandler(threaded.IterableTask):
    def __init__(self, event):
        threaded.IterableTask.__init__(self)
        self.event = event

Handler = IterableHandler

class ServerEvent(Event):
    def __init__(self, server):
        Event.__init__(self)
        self.server = server

    def __str__(self):
        return addr.atos(self.remote)

class ConnectionEvent(ServerEvent):
    def __init__(self, conn, remote, server):
        ServerEvent.__init__(self, server)
        self.conn = conn
        self.remote = remote

    def __str__(self):
        return "Connection from %s" % ServerEvent.__str__(self)

class DatagramEvent(ServerEvent):
    def __init__(self, datagram, remote, server):
        ServerEvent.__init__(self, server)
        self.datagram = datagram
        self.remote = remote

    def __str__(self):
        return "%u-octet datagram from %s" % (len(self.datagram),
            ServerEvent.__str__(self))
