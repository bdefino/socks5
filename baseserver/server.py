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

import socket
import sys
import thread
import time

import event
import eventhandler
import straddress
import threaded

__doc__ = "server core implementation"

class BaseServer(socket.socket, threaded.Threaded):
    """base class for an interruptible server socket"""
    
    def __init__(self, event_class = event.DummyEvent,
            event_handler_class = eventhandler.DummyHandler,
            address = None, backlog = 100, buflen = 512, name = "base",
            nthreads = -1, socket_event_function_name = None, timeout = 0.001,
            type = socket.SOCK_DGRAM):
        if not address: # determine the best default address
            address = ("", 0)

            for addrinfo in socket.getaddrinfo(None, 0):
                address = addrinfo[4]
                break
        af = socket.AF_INET # determine the address family

        if len(address) == 4:
            af = socket.AF_INET6
        elif not len(address) == 2:
            raise ValueError("unknown address family")
        socket.socket.__init__(self, af, type)
        threaded.Threaded.__init__(self, nthreads)
        self.af = af
        self.alive = threaded.Synchronized(True)
        self.backlog = backlog
        self.buflen = buflen
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

    def __call__(self):
        address_string = straddress.straddress(self.address)
        self.sprint("Started", self.name, "server on", address_string)
        
        try:
            for event in self:
                self.execute(self.event_handler_class(event).__call__)
        except KeyboardInterrupt:
            self.alive.set(False)
        finally:
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
    """
    a server which iterates through tasks

    tough to directly subclass, but easy to mimic
    """
    
    def __init__(self, *args, **kwargs):
        BaseServer.__init__(self, *args, **kwargs)
        threaded.Iterative.__init__(self, self.nthreads)

class BaseTCPServer(BaseServer):
    def __init__(self, event_class = event.ConnectionEvent,
            event_handler_class = eventhandler.ConnectionHandler,
            address = None, backlog = 100, buflen = 65536,
            conn_inactive = None, conn_sleep = 0.001, name = "base TCP",
            nthreads = -1, timeout = 0.001):
        BaseServer.__init__(self, event_class, event_handler_class, address,
            backlog, buflen, name, nthreads, "accept", timeout,
            socket.SOCK_STREAM)
        self.conn_inactive = conn_inactive # inactivity period before cleanup
        self.conn_sleep = conn_sleep

    def __call__(self):
        self.listen(self.backlog)
        BaseServer.__call__(self)

class BaseIterativeTCPServer(BaseTCPServer, threaded.Iterative):
    def __init__(self, *args, **kwargs):
        BaseTCPServer.__init__(self, *args, **kwargs)
        threaded.Iterative.__init__(self, self.nthreads)

class BaseUDPServer(BaseServer):
    def __init__(self, event_class = event.DatagramEvent,
            event_handler_class = eventhandler.DatagramHandler, address = None,
            backlog = 100, buflen = 512, name = "base UDP", nthreads = -1,
            timeout = 0.001):
        BaseServer.__init__(self, event_class, event_handler_class, address,
            backlog, buflen, name, nthreads, "recvfrom", timeout)

class BaseIterativeUDPServer(BaseUDPServer, threaded.Iterative):
    def __init__(self, *args, **kwargs):
        BaseUDPServer.__init__(self, *args, **kwargs)
        threaded.Iterative.__init__(self, self.nthreads)
