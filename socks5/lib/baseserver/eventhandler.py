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
import os
import sys

from lib import threaded

__doc__ = "event handling framework"

class EventHandler(threaded.IterableTask):
    """
    the base class for an event handler

    this SHOULD be iterable, though overriding __call__ is acceptable
    when stepping isn't necessary
    """
    
    def __init__(self, event, parent = None):
        threaded.IterableTask.__init__(self)
        self.event = event
        self.parent = parent

class ConnectionHandler(EventHandler):
    pass

class DatagramHandler(EventHandler):
    pass

class DummyHandler(EventHandler):
    pass

class ForkingEventHandler(EventHandler):
    """
    forks when executing __call__,
    but also preserves steppability within the resulting process
    """
    
    def __init__(self, event_handler_class = EventHandler, *args, **kwargs):
        event_handler_class.__init__(self, *args, **kwargs)
        self.event_handler_class = event_handler_class
        self.pid = None
    
    def next(self):
        """fork if the PID was unchanged, then execute and exit"""
        if self.pid == None:
            self.pid = os.fork()

            if self.pid < 0:
                raise OSError("unable to fork")
            elif self.pid > 0:
                if kill_parent:
                    sys.exit(0)
            else: # execute then exit
                try:
                    self.event_handler_class.__call__(self)
                except Exception:
                    pass
                sys.exit()
        raise StopIteration()

class ForkingConnectionHandler(ConnectionHandler, ForkingEventHandler):
    def __init__(self, *args, **kwargs):
        ForkingEventHandler.__init__(self, ConnectionHandler, *args, **kwargs)

class ForkingDatagramHandler(DatagramHandler, ForkingEventHandler):
    def __init__(self, *args, **kwargs):
        ForkingEventHandler.__init__(self, DatagramHandler, *args, **kwargs)

class ForkingDummyHandler(DummyHandler, ForkingEventHandler):
    def __init__(self, *args, **kwargs):
        ForkingEventHandler.__init__(self, DummyHandler, *args, **kwargs)
