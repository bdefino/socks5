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
__doc__ = "general SOCKS5 errors"

class SOCKS5Error(RuntimeError):
    pass

class ResponseError(SOCKS5Error):
    REP_TO_MSG = {1: "general SOCKS server failure",
        2: "connection not allowed by ruleset", 3: "Network unreachable",
        4: "Host unreachable", 5: "Connection refused", 6: "TTL expired",
        7: "Command not supported", 8: "Address type not supported"}

    def __init__(self, rep, *args, **kwargs):
        SOCKS5Error.__init__(self, ResponseError.REP_TO_MSG[rep], *args,
            **kwargs)
