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
import traceback

import addr
import event
from lib import threaded

__doc__ = "an extensible socket server implementation"

class SocketConfig:
    ADDRESS = addr.best()
    BUFLEN = 65536
    DETECTION_TIMEOUT = 0.001
    GENERATING_ATTR = None
    GENERATING_ATTR_ARGS = ()
    GENERATING_ATTR_KWARGS = {}
    SLEEP = 0.001
    TIMEOUT = 0.001
    TYPE = socket.SOCK_RAW

class TCPConfig(SocketConfig):
    BACKLOG = 100
    GENERATING_ATTR = "accept"
    INACTIVE_TIMEOUT = None # guideline for handlers
    SLEEP = 0.01
    TYPE = socket.SOCK_STREAM

class UDPConfig(SocketConfig):
    GENERATING_ATTR = "recvfrom"
    GENERATING_ATTR_ARGS = (SocketConfig.BUFLEN, )
    TYPE = socket.SOCK_DGRAM

class BaseServer:
    """
    the base class for a socket server;
    prints all relevant logging information to STDERR and STDOUT
    
    this follows the event model: the server generates an event,
    then delegates it to a handler;
    if threaded, the server passes the handler
    to the task scheduler (a threaded.Threaded instance),
    which in turn executes the task
    """

    ERROR_PREFIX = "[!]"
    PREFIX = "[*]"

    def __init__(self, event_class = None, handler_class = None,
            sock_config = SocketConfig, stderr = sys.stderr,
            stdout = sys.stdout):
        if not isinstance(sock_config(), SocketConfig):
            raise TypeError("sock_config must inherit from SocketConfig")
        af = socket.AF_INET

        if len(sock_config.ADDRESS) == 4:
            af = socket.AF_INET6
        elif not len(sock_config.ADDRESS) == 2:
            raise ValueError("unknown address family")
        self.alive = threaded.Synchronized(True)
        self.event_class = event_class
        self.handler_class = handler_class
        self.sock_config = sock_config
        self._print_lock = thread.allocate_lock()
        
        self._sock = socket.socket(af, sock_config.TYPE)

        # setsockopts BEFORE bind
        
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self._sock.settimeout(self.sock_config.TIMEOUT)
        self._sock.bind(self.sock_config.ADDRESS)
        
        self.sock_config.ADDRESS = self._sock.getsockname() # update
        self.stderr = stderr
        self.stdout = stdout

    def __call__(self):
        """serve on the socket, then clean up"""
        if self.sock_config.TYPE == socket.SOCK_STREAM:
            backlog = 1
            
            if hasattr(self.sock_config, "BACKLOG"):
                backlog = getattr(self.sock_config, "BACKLOG")
            self._sock.listen(backlog)
        self.sprint(self.PREFIX,
            "Serving on %s" % addr.atos(self.sock_config.ADDRESS))
        
        try:
            while self.alive.get():
                try:
                    event = self.next()
                except StopIteration:
                    break
                self.sprint(self.PREFIX, event)

                if self.handler_class:
                    handler = self.handler_class(event)
                    handle = lambda: handler()

                    if hasattr(self, "_threaded"): # delegate scheduling
                        handle = lambda: getattr(self, "_threaded").put(
                            handler)

                    try:
                        handle()
                    except Exception as e:
                        self.sprinte(self.ERROR_PREFIX, event,
                            traceback.format_exc(e))
        except KeyboardInterrupt:
            pass
        finally:
            self.sprint(self.PREFIX,
                "Closing server on %s" % addr.atos(self.sock_config.ADDRESS))
            self.cleanup()

    def cleanup(self):
        """kill any worker threads and free up the socket resource"""
        self.kill()
        
        if hasattr(self, "_threaded"):
            getattr(self, "_threaded").kill_all()
        
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except socket.error:
            pass
        self._sock.close()
    
    def __iter__(self):
        return self

    def kill(self):
        """signal a graceful exit"""
        self.alive.set(False)

    def next(self):
        """generate an event"""
        if not self.sock_config.GENERATING_ATTR:
            raise StopIteration()
        
        while self.alive.get():
            try:
                _event = getattr(self._sock,
                    self.sock_config.GENERATING_ATTR)(
                        *self.sock_config.GENERATING_ATTR_ARGS,
                        **self.sock_config.GENERATING_ATTR_KWARGS)
            except socket.timeout:
                time.sleep(self.sock_config.SLEEP)
                continue
            
            if self.event_class:
                if not isinstance(_event, tuple):
                    _event = (_event, )
                return self.event_class(*(list(_event) + [self]))
            return _event
        raise StopIteration()

    def sfprint(self, fp, *args):
        """synchronized print to a file"""
        with self._print_lock:
            for a in args:
                print >> fp, a,
            print >> fp

    def sprint(self, *args):
        """synchronized print to STDOUT"""
        self.sfprint(self.stdout, *args)

    def sprinte(self, *args):
        """synchronized print to STDERR"""
        self.sfprint(self.stderr, *args)

    def thread(self, _threaded):
        """thread future events"""
        if _threaded:
            setattr(self, "_threaded", _threaded)

def BaseTCPServer(handler_class = None, sock_config = TCPConfig, *args,
        **kwargs):
    """factory function for a TCP server"""
    if not isinstance(sock_config(), TCPConfig):
        raise TypeError("sock_config must inherit from TCPConfig")
    return BaseServer(event.ConnectionEvent, handler_class, sock_config,
        *args, **kwargs)

def BaseUDPServer(handler_class = None, sock_config = UDPConfig, *args,
        **kwargs):
    """factory function for a UDP server"""
    if not isinstance(sock_config(), UDPConfig):
        raise TypeError("sock_config must inherit from UDPConfig")
    return BaseServer(event.DatagramEvent, handler_class, sock_config,
        *args, **kwargs)
