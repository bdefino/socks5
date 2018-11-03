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
import socket
import sys
import thread
import time

import event
import eventhandler
from lib import threaded
import straddr

__doc__ = "server core implementation"

def best_address(port = 0):
    """return the best default address"""
    for addrinfo in socket.getaddrinfo(None, port):
        return addrinfo[4]
    return ("", port)

class BaseServer(socket.socket):
    """
    base class controlling a server socket
    
    by default, this processes events like so:
        callback(event_handler_class(event_class(event)))
    separating the callback and event handler allows support for both
    functional and object-oriented styles, as well as providing easy
    integration of parallelization

    by default, the callback simply executes the handler

    if the type is recognized (there are known default values),
    unspecified arguments are filled in
    """

    DEFAULTS = {-1: {"backlog": 4096, "buflen": 512,
            "event_class": event.DummyServerEvent,
            "event_handler_class": eventhandler.DummyHandler,
            "timeout": 1 / 1024.0},
        socket.SOCK_DGRAM: {"backlog": 8192, "buflen": 512,
            "event_class": event.DatagramEvent,
            "event_handler_class": eventhandler.DatagramHandler,
            "socket_event_function_name": "recvfrom"},
        socket.SOCK_STREAM: {"backlog": 128, "buflen": 65536,
            "conn_inactive": None, "conn_timeout": 1 / 1024.0,
            "event_class": event.ConnectionEvent,
            "event_handler_class": eventhandler.ConnectionHandler,
            "socket_event_function_name": "accept"}}
    
    def __init__(self, type, callback = lambda h: h(), name = "base",
            stderr = sys.stderr, stdout = sys.stdout, **kwargs):
        if not "address" in kwargs: # must be recalculated
            kwargs["address"] = best_address()
        
        for defaults in (BaseServer.DEFAULTS.get(type, {}), BaseServer.DEFAULTS[-1]):
            for k in defaults: # fill in missing values
                if not k in kwargs:
                    kwargs[k] = defaults[k]
        
        if len(kwargs["address"]) == 2: # determine address family
            kwargs["af"] = socket.AF_INET
        elif len(kwargs["address"]) == 4:
            kwargs["af"] = socket.AF_INET6
        else:
            raise ValueError("unknown address family")
        socket.socket.__init__(self, kwargs["af"], type)

        for k in kwargs:
            setattr(self, k, kwargs[k])
        
        if not hasattr(self, "alive"):
            self.alive = threaded.Synchronized(True)
        elif not isinstance(getattr(self, "alive"), threaded.Synchronized):
            raise TypeError("conflicting types for self.alive")
        self.callback = callback
        self.name = name
        self.sleep = 1.0 / self.backlog # optimal value
        self.bind(self.address)
        self.address = self.getsockname() # in case the OS chose for us
        self.print_lock = thread.allocate_lock()
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.settimeout(self.timeout)
        
        if self.socket_event_function_name \
                and not hasattr(self, self.socket_event_function_name):
            raise ValueError("socket_event_function_name is unusable")
        self.stderr = stderr
        self.stdout = stdout
    
    def __call__(self, max_events = -1):
        if self.type == socket.SOCK_STREAM:
            self.listen(self.backlog)
        address_string = straddr.straddr(self.address)
        self.sprint("Started", self.name, "server on", address_string)
        
        try:
            if max_events:
                for event in self:
                    max_events -= 1
                    self.callback(self.event_handler_class(event))

                    if not max_events:
                        break
        except KeyboardInterrupt:
            pass
        finally:
            self.alive.set(False)
            self.sprint("Closing", self.name,
                "server on %s..." % address_string)
            self.shutdown(socket.SHUT_RDWR)
            self.close()

    def __iter__(self):
        return self

    def next(self):
        """generate events"""
        while 1:
            if not self.alive.get() or not self.socket_event_function_name:
                raise StopIteration()
            
            try:
                return self.event_class(*getattr(self,
                    self.socket_event_function_name)(), server = self)
            except socket.error:
                pass
            time.sleep(self.sleep)
    
    def sfprint(self, fp, *args):
        """synchronized print to file"""
        with self.print_lock:
            for e in args:
                print >> fp, e,
            print >> fp
    
    def sprint(self, *args):
        """synchronized print to stdout"""
        self.sfprint(self.stdout, *args)
    
    def sprinte(self, *args):
        """synchronized print to stderr"""
        self.sfprint(self.stderr, *args)

    def thread(self, _threaded, maintain_callback = False):
        """
        add a threaded component to server

        by default, this replaces the callback entirely;
        this can also maintain the callback (though that isn't desirable with
        the default behavior)
        """
        if maintain_callback: # executes the callback on the handler
            self.callback = lambda h: _threaded.execute(self.callback, h)
        else: # executes the handler
            self.callback = _threaded.execute
