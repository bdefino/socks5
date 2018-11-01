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
import socket

import protocol

__doc__ = "connection authenticator/authorization"
######implement infrastucture for future use of authentication

class AuthError(protocol.error.SOCKS5Error):
    pass

class BaseAuth:
    """authorize/authenticate and wrap a socket"""
    
    def __init__(self, conn, auth_required = False):
        self.auth_required = auth_required
        self.conn = conn
    
    def __call__(self):
        """do auth* as needed and return the wrapped socket"""
        return self.conn

class DummyAuth(BaseAuth):
    pass

class GSSAPIAuth(BaseAuth):
    pass#####################

class NoAuth(BaseAuth):
    """doesn't wrap the socket"""
    
    def __call__(self):
        return

class UsernamePasswordAuth(BaseAuth):
    pass##################

class Auth(BaseAuth):
    """negotiate and use the best auth* method (if possible)"""
    METHOD_TO_AUTH = {0: DummyAuth, 1: GSSAPIAuth, 2: UsernamePasswordAuth,
        255: NoAuth}
    
    def __init__(self, *args, **kwargs):
        BaseAuth.__init__(self, *args, **kwargs)
    
    def __call__(self):
        conn = None
        method_query = protocol.method.MethodQuery()
        method_response = protocol.method.MethodResponse()
        
        try:
            method_query.fload(self.conn.makefile())
            
            for m in method_query.methods:
                if m in Auth.METHOD_TO_AUTH: # attempt to wrap
                    method_response.method = m
                    break

            if self.auth_required and not method_response.method: # failed
                method_response.method = 255
            self.conn.sendall(str(method_response))
            return Auth.METHOD_TO_AUTH[method_response.method](self.conn,
                self.auth_required)()
        except KeyError: # unknown method
            return
        except socket.error:
            return
        return conn
