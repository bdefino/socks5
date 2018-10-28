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
import pack

__doc__ = "method subnegotiation formats"

class MethodQuery:
    """
                   +----+----------+----------+
                   |VER | NMETHODS | METHODS  |
                   +----+----------+----------+
                   | 1  |    1     | 1 to 255 |
                   +----+----------+----------+
    """
    
    def __init__(self, methods = (), nmethods = 0, ver = 5):
        self.methods = methods
        self.nmethods = nmethods
        self.ver = ver

    def fload(self, fp):
        """load from a file-like object"""
        n = 0
        self.ver = pack.unpack(fp.read(1))
        self.nmethods = pack.unpack(fp.read(1))
        self.methods = []

        while n < self.nmethods: # more efficient
            self.methods.append(pack.unpack(fp.read(1)))
            n += 1
        self.methods = tuple(self.methods)

    def __str__(self):
        query = [pack.pack(self.version, 1), pack.pack(self.nmethods, 1)] \
            + [pack.pack(m, 1) for m in self.methods]
        return "".join(query)

class MethodResponse:
    """
                         +----+--------+
                         |VER | METHOD |
                         +----+--------+
                         | 1  |   1    |
                         +----+--------+
    """

    def __init__(self, method = 0, ver = 5):
        self.method = method
        self.ver = ver

    def fload(self, fp):
        """load from a file-like object"""
        self.ver = pack.unpack(fp.read(1))
        self.method = pack.unpack(fp.read(1))

    def __str__(self):
        return "".join((pack.pack(self.ver, 1), pack.pack(self.method, 1)))
