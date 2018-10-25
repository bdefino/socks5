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
__package__ = "baseserver"

__doc__ = "events"

class Event:
    def __init__(self):
        pass

class ServerEvent(Event):
    def __init__(self, server):
        Event.__init__(self)
        self.server = server

class ConnectionEvent(ServerEvent):
    def __init__(self, conn, remote, server):
        ServerEvent.__init__(self, server)
        self.conn = conn
        self.remote = remote

class DatagramEvent(ServerEvent):
    def __init__(self, datagram, remote, server):
        ServerEvent.__init__(self, server)
        self.datagram = datagram
        self.remote = remote

class DummyEvent(ServerEvent):
    def __init__(self, event, remote, server):
        ServerEvent.__init__(self, server)
        self.event = event
