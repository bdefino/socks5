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

__doc__ = "configuration files"

global DEFAULT_CONF_FLAVOR

class ConfFlavor:
    """
    rudimentary flavor for a configuration file

    note that when a comment evaluates to False (False, None, "", 0),
    we assume there are no comments
    """

    def __init__(self, assignment = ':', comment = '#'):
        assert not assignment == comment, "conflicting delimiters"
        self.assignment = assignment
        self.comment = comment

DEFAULT_CONF_FLAVOR = ConfFlavor()

class Conf(dict):
    """
    a basic configuration file reader/writer with dict-like behavior

    autosync specifies whether to automatically synchronize primary
    and secondary storage of the configuration file
    """

    def __init__(self, path = None, expect = None,
            flavor = DEFAULT_CONF_FLAVOR, autosync = True):
        dict.__init__(self)
        self.autosync = autosync

        if expect:
            expect = set(expect)
        self._expect = expect # the dictionary keys we should expect
        self.flavor = flavor
        self.path = path

        if self.path:
            self.read()

    def add(self, key, value):
        """
        add a key, value pair to the configuration file

        the key may already exist
        """
        if self.has_key(key):
            if not isinstance(self[key], list):
                dict.__setitem__(self, key, [self[key]])
            self[key].append(value)
        else:
            dict.__setitem__(self, key, value)

        if self.autosync:
            self.write()

    def clear(self):
        dict.clear(self)
        
        if self.autosync:
            self.write()

    def __delitem__(self, key):
        dict.__delitem__(self, key)

        if self.autosync:
            self.write()

    def load(self, string):
        """load from a string"""
        self.clear()
        lines = string.split('\n')
        
        if lines:
            for i in range(len(lines) - 1, -1, -1): # strip comments
                l = lines[i]

                if self.flavor.comment and self.flavor.comment in l:
                    l = l[:l.find(self.flavor.comment)]
                l = l.strip()

                if l:
                    lines[i] = l
                else:
                    del lines[i]

        for l in lines: # parse assignments
            k = l
            v = None

            if self.flavor.assignment in l:
                k, v = [e.strip() for e in l.split(self.flavor.assignment, 1)]
            self.add(k, v) # set/append as needed

        if self._expect and not self._expect == set(self.keys()):
            raise ValueError("missing and/or additional keys")

    def read(self):
        """load from path"""
        if not self.flavor or not self.path:
            raise ValueError("invalid flavor and/or path attribute")
        data = ""
        
        with open(self.path, "rb") as fp:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            data = fp.read()
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
        self.load(data)

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)

        if self.autosync:
            self.write()

    def __str__(self):
        """convert to string"""
        lines = []

        for k, vs in self.items():
            k = str(k)

            if vs == None:
                lines.append(k)
                continue
            elif not isinstance(vs, list):
                vs = [vs]
            
            for v in vs:
                lines.append(k + self.flavor.assignment + ' ' + str(v))
        return '\n'.join(sorted(lines))

    def write(self, outpath = None):
        """write to path"""
        if not outpath:
            outpath = self.path

        with open(outpath, "wb") as fp:
            fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
            fp.write(self.__str__())
            os.fdatasync(fp.fileno())
            fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
