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

import error
import header

__doc__ = """
connection authentication

this also handles the authentication method subnegotiation
"""
####################################username/password implementation
########migrate from individual authenticators to multi-method abstractions
###################rethink API: OO vs. static methods

def wrap_socket(sock, server_side = False, *authenticators):
    """
    attempt to wrap a socket using the most
    desirable authentication method
    """
    return DelegatingAuthenticator(server_side, *authenticators)(sock)

class AuthenticationError(error.SOCKS5Error):
    pass

class AuthenticationFailed(AuthenticationError):
    pass

class BaseAuthenticator:
    """base class for connection authentication"""
    
    def __init__(self, method, server_side = False):
        self.method = method
        self.server_side = server_side

    def __call__(self, conn):
        """MUST return a (wrapped) connection or None"""
        return conn

class DelegatingAuthenticator(BaseAuthenticator):
    """abstraction for multiple authenticators"""
    
    def __init__(self, server_side = False, *authenticators):
        BaseAuthenticator.__init__(self, -1, server_side)

        if not authenticators:
            authenticators = (DummyAuthenticator(self.server_side), )
        self.authenticators = {a.method: a for a in authenticators}

        for a in self.authenticators.values():
            if not a.server_side == self.server_side:
                raise ValueError("authenticators must agree on server_side")
    
    def __call__(self, sock):
        """negotiate the authentication method and delegate authentication"""
        return self.authenticators[MethodNegotiator.negotiate(sock,
            self.authenticators.keys(), self.server_side)](sock)

class DummyAuthenticator(BaseAuthenticator):
    def __init__(self, *args, **kwargs):
        BaseAuthenticator.__init__(self, 0, *args, **kwargs)

class FailingAuthenticator(BaseAuthenticator):
    """informs the caller that authentication failed"""

    def __init__(self, *args, **kwargs):
        BaseAuthenticator.__init__(self, 255, *args, **kwargs)
    
    def __call__(self):
        raise AuthenticationError()

class GSSAPIAuthenticator(BaseAuthenticator):
    ##########################################
    def __init__(self, *args, **kwargs):
        BaseAuth.__init__(self, 1, *args, **kwargs)
        raise NotImplementedError()

class MethodNegotiationError(error.SOCKS5Error):
    pass

class MethodNegotiationFailed(MethodNegotiationError):
    pass

class MethodNegotiator:
    """negotiates the authentication method"""
    
    @staticmethod
    def negotiate(sock, methods = (0, ), server_side = False):
        """delegate method negotiation"""
        if server_side:
            return MethodNegotiator.negotiate_server_side(sock, methods)
        return MethodNegotiator.negotiate_client_side(sock, methods)

    @staticmethod
    def negotiate_client_side(sock, methods = (0, )):
        """negotiate the method as a client"""
        response_header = header.MethodResponseHeader()
        
        try:
            sock.sendall(str(header.MethodQueryHeader(methods, len(methods))))
            response_header.fload(sock.makefile())
        except socket.error as e:
            raise MethodNegotiationError(*e.args)

        if response_header.method == 255:
            raise MethodNegotiationFailed()
        return response_header.method

    @staticmethod
    def negotiate_server_side(sock, accepted_methods = (0, )):
        """negotiate the method as a server"""
        accepted_methods = {m: None for m in accepted_methods} # quick access
        query_header = header.MethodQueryHeader()
        selected_method = 255
        
        try:
            query_header.fload(sock.makefile())
        except socket.error as e:
            raise MethodNegotiationError(*e.args)
        
        for m in query_header.methods:
            if m in accepted_methods:
                selected_method = m
                break

        try:
            sock.sendall(str(header.MethodResponseHeader(selected_method)))
        except socket.error as e:
            raise MethodNegotiationError(*e.args)
        
        if selected_method == 255:
            raise MethodNegotiationFailed()
        return selected_method

class UsernamePasswordAuthenticator(BaseAuthenticator):
    """RFC 1929-compliant authentication"""
    ########################################
    
    def __init__(self, username_to_password = {}, *args, **kwargs):
        BaseAuthenticator.__init__(self, 2, *args, **kwargs)
        self.__call__ = self.authenticate_client_side

        if self.server_side:
            self.__call__ = self.authenticate_server_side
        self.username_to_password = username_to_password
    
    def authenticate_client_side(self, conn):
        pass

    def authenticate_server_side(self, conn):
        pass
