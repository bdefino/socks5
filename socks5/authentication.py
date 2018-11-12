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
import packet

__doc__ = """
connection authentication

this also handles the authentication method subnegotiation
"""
######################################GSSAPI

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

    def __call__(self, sock):
        """MUST return (wrapped socket, authentication info) or complain"""
        return sock, None

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
    """authentication via GSSAPI"""
    ##########################################
    
    def __init__(self, *args, **kwargs):
        BaseAuthenticator.__init__(self, 1, *args, **kwargs)
        raise NotImplementedError()##############################

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
        query = packet.MethodQuery(methods, len(methods))
        response = packet.MethodResponse()
        
        try:
            sock.sendall(str(query))
            response.fload(sock.makefile())
        except IOError as e:
            raise MethodNegotiationError(*e.args)

        if response.method == 255:
            raise MethodNegotiationFailed()
        return response.method

    @staticmethod
    def negotiate_server_side(sock, accepted_methods = (0, )):
        """negotiate the method as a server"""
        accepted_methods = {m: None for m in accepted_methods} # quick access
        query = packet.MethodQuery()
        response = packet.MethodResponse(255)
        
        try:
            query.fload(sock.makefile())
        except IOError as e:
            raise MethodNegotiationError(*e.args)
        
        for m in query.methods:
            if m in accepted_methods:
                response.method = m
                break
        
        try:
            sock.sendall(str(response))
        except socket.error as e:
            raise MethodNegotiationError(*e.args)
        
        if response.method == 255:
            raise MethodNegotiationFailed()
        return response.method

class UsernamePasswordAuthenticator(BaseAuthenticator):
    """RFC 1929-compliant authentication"""
    
    def __init__(self, username_to_password = {}, *args, **kwargs):
        BaseAuthenticator.__init__(self, 2, *args, **kwargs)
        self.__call__ = self.authenticate_client_side

        if self.server_side: # check once and only once
            self.__call__ = self.authenticate_server_side
        elif not len(username_to_password) == 1:
            raise ValueError("exactly one username/password pair required")
        self.username_to_password = username_to_password
    
    def authenticate_client_side(self, sock):
        """authenticate a socket as a client"""
        response = packet.UsernamePasswordResponse()
        username, password = self.username_to_password.iteritems().next()
        request = packet.UsernamePasswordRequest(password,
            len(password), len(username), username)
        
        try:
            sock.sendall(str(request))
            response.fload(sock.makefile())
        except IOError as e:
            raise AuthenticationError(*e.args)

        if response.status:
            raise AuthenticationFailed()
        return sock, None

    def authenticate_server_side(self, sock):
        """
        authenticate a socket as a server
        
        return (wrapped socket, username) or complain
        """
        auth_info = None
        request = packet.UsernamePasswordRequest()
        response = packet.UsernamePasswordResponse(255)
        
        try:
            request.fload(sock.makefile())
        except IOError as e:
            raise AuthenticationError(*e.args)
        expected_password = self.username_to_password.get(request.uname)

        if expected_password and request.passwd == expected_password:
            response.status = 0

        try:
            sock.sendall(str(response))
        except socket.error as e:
            raise AuthenticationError(*e.args)

        if response.status:
            raise AuthenticationFailed()
        return sock, request.uname
