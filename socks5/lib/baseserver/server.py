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
    base class for an interruptible server socket
    
    this processes events like so:
        callback(event_handler_class(event_class(event)))
    separating the callback and event handler allows support for both
    functional and object-oriented styles, as well as providing easy
    integration of parallelization
    """
    
    def __init__(self, address = None, backlog = 100, buflen = 512,
            callback = lambda e: None, event_class = event.DummyServerEvent,
            event_handler_class = eventhandler.DummyHandler,
            name = "base", socket_event_function_name = None, timeout = 0.001,
            type = socket.SOCK_DGRAM):
        if not address: # use the best default address
            address = best_address()
        af = socket.AF_INET # determine the address family

        if len(address) == 4:
            af = socket.AF_INET6
        elif not len(address) == 2:
            raise ValueError("unknown address family")
        socket.socket.__init__(self, af, type)
        self.af = af

        if not hasattr(self, "alive"):
            self.alive = threaded.Synchronized(True)
        elif not isinstance(getattr(self, "alive"), threaded.Synchronized):
            raise TypeError("conflicting types for \"alive\":" \
                " multiple inheritance issue?")
        self.backlog = backlog
        self.buflen = buflen
        self.callback = callback
        self.event_class = event_class
        self.event_handler_class = event_handler_class
        self.name = name
        self.sleep = 1.0 / self.backlog # optimal value
        self.bind(address)
        self.address = self.getsockname() # by default, address is undefined
        self.print_lock = thread.allocate_lock()
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.settimeout(timeout)
        self.socket_event_function_name = socket_event_function_name
        self.timeout = timeout

    def __call__(self, max_events = -1):
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
    
    def sprint(self, *args):
        """synchronized print"""
        self.sfprint(sys.stdout, *args)

    def sfprint(self, fp, *args):
        """synchronized print to file"""
        with self.print_lock:
            for e in args:
                print >> fp, e,
            print >> fp

class BaseIterativeServer(BaseServer, threaded.Iterative):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DummyServerEvent,
            event_handler_class = eventhandler.DummyHandler,
            name = "base iterative", nthreads = -1, queue_output = False,
            socket_event_function_name = None, timeout = 0.001,
            type = socket.SOCK_DGRAM):
        BaseServer.__init__(self, address, backlog, buflen, self.execute,
            event_class, event_handler_class, name, socket_event_function_name,
            timeout, type)
        threaded.Iterative.__init__(self, nthreads, queue_output, self.timeout)

class BaseIterativeTCPServer(BaseIterativeServer):
    def __init__(self, address = None, backlog = 100, buflen = 65536,
            conn_inactive = None, conn_sleep = 0.001,
            event_class = event.ConnectionEvent,
            event_handler_class = eventhandler.ConnectionHandler,
            name = "base iterative TCP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BaseIterativeServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "accept", timeout, socket.SOCK_STREAM)
        self.conn_inactive = conn_inactive # inactivity period before cleanup
        self.conn_sleep = conn_sleep

    def __call__(self):
        self.listen(self.backlog)
        BaseServer.__call__(self)

class BaseIterativeUDPServer(BaseIterativeServer):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DatagramEvent,
            event_handler_class = eventhandler.DatagramHandler,
            name = "base iterative UDP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BaseIterativeServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "recvfrom", timeout)

class BasePipeliningServer(BaseServer, threaded.Pipelining):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DummyServerEvent,
            event_handler_class = eventhandler.DummyHandler,
            name = "base pipelining", nthreads = -1, queue_output = False,
            socket_event_function_name = None, timeout = 0.001,
            type = socket.SOCK_DGRAM):
        BaseServer.__init__(self, address, backlog, buflen, self.execute,
            event_class, event_handler_class, name, socket_event_function_name,
            timeout, type)
        threaded.Pipelining.__init__(self, nthreads, queue_output,
            self.timeout)

class BasePipeliningTCPServer(BasePipeliningServer):
    def __init__(self, address = None, backlog = 100, buflen = 65536,
            conn_inactive = None, conn_sleep = 0.001,
            event_class = event.ConnectionEvent,
            event_handler_class = eventhandler.ConnectionHandler,
            name = "base pipelining TCP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BasePipeliningServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "accept", timeout, socket.SOCK_STREAM)
        self.conn_inactive = conn_inactive # inactivity period before cleanup
        self.conn_sleep = conn_sleep

    def __call__(self):
        self.listen(self.backlog)
        BaseServer.__call__(self)

class BasePipeliningUDPServer(BasePipeliningServer):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DatagramEvent,
            event_handler_class = eventhandler.DatagramHandler,
            name = "base pipelining UDP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BasePipeliningServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "recvfrom", timeout)

class BaseTCPServer(BaseServer):
    def __init__(self, address = None, backlog = 100, buflen = 65536,
            callback = lambda e: None, conn_inactive = None,
            conn_sleep = 0.001, event_class = event.ConnectionEvent,
            event_handler_class = eventhandler.ConnectionHandler,
            name = "base TCP", timeout = 0.001):
        BaseServer.__init__(self, address, backlog, buflen, callback,
            event_class, event_handler_class, name, "accept", timeout,
            socket.SOCK_STREAM)
        self.conn_inactive = conn_inactive # inactivity period before cleanup
        self.conn_sleep = conn_sleep

    def __call__(self):
        self.listen(self.backlog)
        BaseServer.__call__(self)

class BaseThreadedServer(BaseServer, threaded.Threaded):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DummyServerEvent,
            event_handler_class = eventhandler.DummyHandler,
            name = "base threaded", nthreads = -1, queue_output = False,
            socket_event_function_name = None, timeout = 0.001,
            type = socket.SOCK_DGRAM):
        BaseServer.__init__(self, address, backlog, buflen, self.execute,
            event_class, event_handler_class, name, socket_event_function_name,
            timeout, type)
        threaded.Threaded.__init__(self, nthreads, queue_output)

class BaseThreadedTCPServer(BaseThreadedServer):
    def __init__(self, address = None, backlog = 100, buflen = 65536,
            conn_inactive = None, conn_sleep = 0.001,
            event_class = event.ConnectionEvent,
            event_handler_class = eventhandler.ConnectionHandler,
            name = "base iterative TCP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BaseThreadedServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "accept", timeout, socket.SOCK_STREAM)
        self.conn_inactive = conn_inactive # inactivity period before cleanup
        self.conn_sleep = conn_sleep

    def __call__(self):
        self.listen(self.backlog)
        BaseServer.__call__(self)

class BaseThreadedUDPServer(BaseThreadedServer):
    def __init__(self, address = None, backlog = 100, buflen = 512,
            event_class = event.DatagramEvent,
            event_handler_class = eventhandler.DatagramHandler,
            name = "base threaded UDP", nthreads = -1, queue_output = False,
            timeout = 0.001):
        BaseThreadedServer.__init__(self, address, backlog, buflen,
            event_class, event_handler_class, name, nthreads, queue_output,
            "recvfrom", timeout)

class BaseUDPServer(BaseServer):
    def __init__(self, address = None,
            backlog = 100, buflen = 512, callback = lambda e: None,
            event_class = event.DatagramEvent,
            event_handler_class = eventhandler.DatagramHandler,
            name = "base UDP", timeout = 0.001):
        BaseServer.__init__(self, address, backlog, buflen, callback,
            event_class, event_handler_class, name, "recvfrom", timeout)
