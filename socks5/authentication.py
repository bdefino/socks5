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

def negotiate_method(sock, methods = (0, ), server_side = False):
    pass

def wrap_socket(sock, methods = (0, ), server_side = False, **auth_kwargs):
    """
    attempt to wrap a socket using the most
    desirable authentication method
    """
    return Authenticator(MethodNegotiator.negotiate(sock, methods, server_side),
        server_side, **auth_kwargs)(sock)

class AuthenticationError(error.SOCKS5Error):
    pass

class AuthenticationFailed(AuthenticationError):
    pass

class BaseAuthenticator:
    """base class for connection authentication"""
    
    def __init__(self, server_side = False, *args, **kwargs):
        self.server_side = server_side

    def __call__(self, conn):
        """MUST return a (wrapped) connection or None"""
        return conn

class DummyAuthenticator(BaseAuthenticator):
    pass

class FailingAuthenticator(BaseAuthenticator):
    """informs the caller that authentication failed"""
    
    def __call__(self):
        raise AuthenticationError()

class GSSAPIAuthenticator(BaseAuthenticator):
    ##########################################
    def __init__(self, *args, **kwargs):
        BaseAuth.__init__(self, *args, **kwargs)
        raise NotImplementedError()

class MethodNegotiationError(error.SOCKS5Error):
    pass

class MethodNegotiationFailed(MethodNegotiationError):
    pass

class MethodNegotiator:
    """negotiate authentication method"""
    
    @staticmethod
    def negotiate(conn, methods = (0, ), server_side = False):
        if server_side:
            return MethodNegotiator.negotiate_server_side(conn, methods)
        return MethodNegotiator.negotiate_client_side(conn, methods)

    @staticmethod
    def negotiate_client_side(conn, methods = (0, )):
        response_header = header.MethodResponseHeader()
        
        try:
            conn.sendall(str(header.MethodQueryHeader(methods, len(methods))))
            response_header.fload(conn.makefile())
        except socket.error as e:
            raise MethodNegotiationError(*e.args)

        if response_header.method == 255:
            raise MethodNegotiationFailed()
        return response_header.method

    @staticmethod
    def negotiate_server_side(conn, accepted_methods = (0, )):
        accepted_methods = {m: None for m in accepted_methods} # quick access
        query_header = header.MethodQueryHeader()
        selected_method = 255
        
        try:
            query_header.fload(conn.makefile())
        except socket.error as e:
            raise MethodNegotiationError(*e.args)
        
        for m in query_header.methods:
            if m in accepted_methods:
                selected_method = m
                break

        try:
            conn.sendall(str(header.MethodResponseHeader(
                selected_method)))
        except socket.error as e:
            raise MethodNegotiationError(*e.args)
        
        if selected_method == 255:
            raise MethodNegotiationFailed()
        return selected_method

class UsernamePasswordAuthenticator(BaseAuthenticator):
    """RFC 1929-compliant authentication"""
    ########################################
    
    def __init__(self, server_side = False, username_to_password = {}, *args,
            **kwargs):
        BaseAuthenticator.__init__(self, server_side, *args, **kwargs)
        self.__call__ = self.authenticate_client_side

        if self.server_side:
            self.__call__ = self.authenticate_server_side
        self.username_to_password = username_to_password
    
    def authenticate_client_side(self, conn):
        pass

    def authenticate_server_side(self, conn):
        pass

class Authenticator(object):
    """authentication method factory"""
    METHOD_TO_AUTHENTICATOR = {0: DummyAuthenticator, 1: GSSAPIAuthenticator,
        2: UsernamePasswordAuthenticator, 255: FailingAuthenticator}
    
    def __new__(self, method = 0, *args, **kwargs):
        try:
            return Authenticator.METHOD_TO_AUTHENTICATOR[method](*args,
                **kwargs)
        except KeyError:
            raise ValueError("unknown method")
