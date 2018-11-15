# Copyright (C) 2018 Bailey Defino
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
import fcntl
import os
import socket
import sys
import traceback

import baseserver
import event
import eventhandler
import straddr

__doc__ = "a simple HTTP server"

def http_bufsize(max):
    """return the highest positive power of 2 <= max"""
    exp = 1
    max = min(4096, max) # keep it reasonable
    
    while 2 << exp <= max:
        exp += 1
    return 2 << (exp - 1)

class HTTPHeaders(dict):
    """
    a dictionary of strings mapped to values

    useful for loading MIME headers from a file-like object
    """
    
    def __init__(self, **kwargs):
        dict.__init__(self)

        for k in kwargs.keys():
            self.__setitem__(k, kwargs[k])

    def add(self, key, value):
        """same as __setitem__, but preserves multiple, ordered values"""
        if not isinstance(key, str):
            raise KeyError("key must be a str")
        key = key.strip().lower()

        if isinstance(value, tuple):
            value = list(value)
        
        if self.has_key(key):
            current_value = self.__getitem__(key)

            if isinstance(current_value, tuple):
                current_value = list(current_value)
            elif not isinstance(current_value, list):
                current_value = [current_value]

            if not isinstance(value, list):
                value = [value]
            current_value += value
            dict.__setitem__(self, key, current_value)
        else:
            self.__setitem__(key, value)

    def fload(self, fp):
        """load from a file-like object"""
        line = []

        while not "".join(line) in ("\n", "\r\n"): # read the headers
            try:
                line.append(fp.read(1))
            except socket.timeout:
                continue

            if line and line[-1] == '\n':
                if ':' in line:
                    k, v = "".join(line).split(':', 1)
                    v = v.strip()

                    for _type in (int, float): # cast numerics
                        try:
                            v = _type(v)
                            break
                        except ValueError:
                            pass
                    self.add(k.strip(), v)
                    line = []
                elif "".join(line).rstrip("\r\n"):
                    line = list("".join(line).strip() + ' ') # multiline
    
    def get(self, key, default = None):
        if not isinstance(key, str):
            raise KeyError("key must be a str")
        key = key.strip()
        
        if self.has_key(key):
            return self.__getitem__(key)
        return default

    def __getitem__(self, key):
        if not isinstance(key, str):
            raise KeyError("key must be a str")
        return dict.__getitem__(self, key.strip().lower())

    def __setitem__(self, key, value):
        if not isinstance(key, str):
            raise KeyError("key must be a str")
        dict.__setitem__(self, key.strip().lower(), value)

    def __str__(self):
        """convert to string, WITH the empty line terminator"""
        pairs = []
        
        for k, v in sorted(self.iteritems(), key = lambda e: e[0]):
            k = k.capitalize()
            
            if isinstance(v, list):
                for _v in v:
                    pairs.append((k, _v))
            else:
                pairs.append((k, v))
        return "\r\n".join([": ".join((k, str(v))) for k, v in pairs]
            + ["", ""])

class HTTPRequest:
    def __init__(self, headers = None, method = None, resource = None,
            version = 0):
        if not headers:
            headers = HTTPHeaders()
        self.headers = headers
        self.method = method
        self.resource = resource
        self.version = version

    def fload(self, fp):
        """load from a file-like object"""
        self.method = []
        self.resource = []
        self.version = []
        
        while not self.method or not self.method[-1] == ' ':
            try:
                self.method.append(fp.read(1))
            except socket.timeout:
                pass
        self.method = "".join(self.method).strip()

        while not self.resource or not self.resource[-1] == ' ':
            try:
                self.resource.append(fp.read(1))
            except socket.timeout:
                pass
        self.resource = "".join(self.resource).strip()
        
        while not self.version or not self.version[-1] == '\n':
            try:
                self.version.append(fp.read(1))
            except socket.timeout:
                pass
        self.version = "".join(self.version).strip()

        if '/' in self.version:
            self.version = self.version[self.version.rfind('/') + 1:]
        self.version = float(self.version)
        self.headers = HTTPHeaders()
        self.headers.fload(fp)

class HTTPRequestEvent(event.ConnectionEvent):
    def __init__(self, request, *args, **kwargs):
        event.ConnectionEvent.__init__(self, *args, **kwargs)
        self.request = request

class HTTPRequestHandler(eventhandler.EventHandler):
    def __init__(self, *args, **kwargs):
        eventhandler.EventHandler.__init__(self, *args, **kwargs)
        self.code = 200
        self.headers = HTTPHeaders()
        self.headers["connection"] = "close"
        self.headers["content-length"] = 0
        self.message = "OK"

    def next(self):
        try:
            self.respond()
        except socket.error:
            pass
        raise StopIteration()

    def respond(self):
        """send the appropriate headers"""
        self.event.conn.sendall("HTTP/%.1f %u %s\r\n" % (
            float(self.event.request.version), int(self.code),
            str(self.message)) + str(self.headers)) # includes terminator

class GETHandler(HTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        HTTPRequestHandler.__init__(self, *args, **kwargs)
        self.content_length = -1
        self.fp = None
        self.locked = False
        self.path = self.event.server.resolver(self.event.request.resource)
        
        if os.path.exists(self.path) and not os.path.isdir(self.path):
            try:
                self.fp = open(self.path, "rb")
                self.fp.seek(0, os.SEEK_END)
                self.content_length = self.fp.tell()
                self.headers["content-length"] = self.content_length
                self.fp.seek(0, os.SEEK_SET)
            except (IOError, OSError):
                self.code = 500
                self.message = "Internal Server Error"
        else:
            self.code = 404
            self.message = "Not Found"
        
        if self.fp: # path is inherently nonexistent
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX)
                self.locked = True
            except IOError:
                self.code = 500
                self.message = "Internal Server Error"

        try:
            HTTPRequestHandler.respond(self) # send response header
        except socket.error: # the file will eventually be closed
            self.locked = False

    def next(self):
        if self.locked:
            if self.content_length: # fp is inherently open
                try:
                    chunk = self.fp.read(http_bufsize(self.content_length))
                    self.content_length -= len(chunk)
                    self.event.conn.sendall(chunk)
                except IOError:
                    pass
                return
            
            try:
                fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
            except IOError:
                pass
            self.locked = False
        
        if self.fp: # may not have been locked
            try:
                self.fp.close()
            except (IOError, OSError):
                pass
            self.fp = None
        raise StopIteration()

class HEADHandler(HTTPRequestHandler):
    def next(self):
        path = self.event.server.resolver(self.event.request.resource)
        
        if os.path.exists(path) and not os.path.isdir(path):
            try:
                with open(path, "rb") as fp:
                    fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
                    fp.seek(0, os.SEEK_END)
                    self.headers["content-length"] = fp.tell()
                    fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
            except (IOError, OSError):
                self.code = 500
                self.message = "Internal Server Error"
        else:
            self.code = 404
            self.message = "Not Found"
        HTTPRequestHandler.next(self) # respond/stop

class HTTPConnectionHandler(eventhandler.EventHandler):
    """
    parse an HTTP header and execute the appropriate handler

    adding to METHOD_TO_HANDLER is the easiest way to modify capabilities

    this class is intended to be used as a template for handling
    different types of requests
    """
    
    METHOD_TO_HANDLER = {"GET": GETHandler, "HEAD": HEADHandler}
    
    def __init__(self, *args, **kwargs):
        eventhandler.EventHandler.__init__(self, *args, **kwargs)
        request = HTTPRequest()
        self.address_string = straddr.straddr(self.event.remote)
        self.request_handler = None
        
        try:
            self.event.conn.settimeout(self.event.server.timeout)
            request.fload(self.event.conn.makefile())
            
            self.event.server.sprint("Handling", request.method, "request for",
                request.resource, "from", self.address_string)
            
            self.request_handler = HTTPConnectionHandler.METHOD_TO_HANDLER[
                request.method](HTTPRequestEvent(request, self.event.conn,
                    self.event.remote, self.event.server))
        except KeyError: # method not supported
            _request_handler = HTTPRequestHandler(request, self.event.conn,
                self.event.remote, self.event.server)
            _request_handler.code = 501
            _request_handler.status = "Not Supported"
            
            try:
                _request_handler.respond()
            except socket.error:
                pass
            self.request_handler = None
        except Exception:
            self.event.server.sprinte(
                "ERROR while handling connection with %s:\n"
                    % self.address_string, traceback.format_exc())
            self.request_handler = None
    
    def next(self):
        if self.event.server.alive.get() and self.request_handler:
            try:
                return self.request_handler.next()
            except StopIteration:
                pass
            except Exception:
                self.event.server.sfprint(sys.stderr,
                    "ERROR while handling connection with %s:\n"
                        % self.address_string, traceback.format_exc())
        self.event.server.sprint("Closing connection with",
            self.address_string)

        for f in (lambda: self.event.conn.shutdown(socket.SHUT_RDWR),
                self.event.conn.close):
            try:
                f()
            except socket.error:
                pass
        self.request_handler = None
        eventhandler.ConnectionHandler.next(self) # shutdown, close, and stop

class BaseHTTPServer(baseserver.BaseServer):
    """
    a simple HTTP server

    regarding the resource resolver:
        isolate: keep resources within the root
        root: the content root directory
    """
    
    def __init__(self, event_handler_class = HTTPConnectionHandler,
            isolate = True, name = "HTTP", root = os.getcwd(), **kwargs):
        baseserver.BaseServer.__init__(self, socket.SOCK_STREAM,
            event_handler_class = event_handler_class, name = name, **kwargs)
        _resolver = lambda r: r
        
        if isolate:
            _resolver = lambda r: os.path.normpath(r).lstrip('/')
        self.resolver = lambda r: os.path.join(root, _resolver(r))
        self.root = root

        if not os.path.exists(self.root):
            os.makedirs(self.root)
