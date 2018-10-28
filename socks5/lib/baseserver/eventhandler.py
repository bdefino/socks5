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
    
    def __init__(self, *args, **kwargs):
        EventHandler.__init__(self, *args, **kwargs)
        self.pid = None

    def __call__(self, kill_parent = False):
        """fork before execution"""
        if self.pid == None:
            self.pid = os.fork()

            if self.pid < 0:
                raise OSError("unable to fork")
            elif self.pid > 0:
                if kill_parent:
                    sys.exit(0)
                return
        threaded.IterableTask.__call__(self)
