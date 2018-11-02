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

from event import ConnectionEvent, Event, DatagramEvent, DummyServerEvent,  \
    ServerEvent, ThreadedEvent
from eventhandler import ConnectionHandler, DatagramHandler, DummyHandler, \
    EventHandler, ForkingConnectionHandler, ForkingDatagramHandler, \
    ForkingDummyHandler, ForkingEventHandler
from lib import threaded
from server import BaseServer, best_address
from straddr import parseaddr, straddr

__doc__ = """
a simple server framework

basic flow:
    1. if there's a kill order, stop
    2. listen for an event
    3. create a handler for the event
    4. pass the handler to the callback
    5. repeat from step 1
"""
