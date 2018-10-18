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
__package__ = "socks5"

import method

__doc__ = "connection authenticator"
######implement infrastucture for future use of authentication

class Authenticator:
    def __init__(self, conn, authenticate = False):
        self.conn = conn
    
    def __call__(self):##########
        method_query = method.MethodQuery()
        
        try:
            method_query.fload(self.conn.makefile())
            self.conn.sendall(str(method.MethodResponse())) # no authentication
        except socket.error:
            return
        return self.conn
