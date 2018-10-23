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

import os

import events
import steppable

__doc__ = "event handling framework"

class EventHandler(steppable.Steppable):
    """
    the base class for an event handler

    this SHOULD be steppable, though overriding __call__ is acceptable
    when stepping isn't necessary
    """
    
    def __init__(self, event):
        steppable.Steppable.__init__(self)
        self.event = event

class ConnectionHandler(EventHandler):
    pass

class DatagramHandler(EventHandler):
    pass

class DummyHandler(EventHandler):
    pass

class ForkingEventHandler(EventHandler):
    """
    forks when executing __call__,
    but also allows steppability in the current process
    """
    
    def __init__(self, event):
        EventHandler.__init__(self, event)
        self.pid = None

    def __call__(self):
        """fork before execution"""
        if self.pid == None:
            self.pid = os.fork()

            if self.pid < 0:
                raise OSError("unable to fork")
            elif self.pid > 0:
                return
        steppable.Steppable.__call__(self)
