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
__package__ = __name__

import fcntl
import os
import StringIO

__doc__ = """
simple configuration files adhering to the following configurable format:
    TITLE START + "title" + TITLE END + '\n'
    "key" + ASSIGNMENT OPERATOR + "value" + COMMENT + "comment" + '\n'
the same format using the default flavor:
    [title]
    key:value#comment
"""

global DEFAULT_CONF_FLAVOR

def guess_type(string):
    """attempt to guess a string's type (float, int, long, str)"""
    if not isinstance(string, str):
        raise TypeError("string should be a string")
    accepted = [] # ordered from most preferable to least preferable
    
    for t in (int, float, long, str): # order matters
        try:
            t(string)
            accepted.append(t)
        except ValueError:
            pass
    return accepted[0]

class ConfFlavor:
    """
    configuration file syntax

    checks for syntax conflicts
    """
    
    def __init__(self, assignment = ':', comment = '#', title_end = ']',
            title_start = '['):
        delims = filter(None, (assignment, comment, title_end, title_start))

        for ai, a in enumerate(delims): # unfortunately O(n**2)
            for bi, b in enumerate(delims):
                if not ai == bi and (a in b or b in a):
                    raise ValueError("conflicting syntax")
        self.assignment = assignment
        self.comment = comment
        self.title_end = title_end
        self.title_start = title_start

DEFAULT_CONF_FLAVOR = ConfFlavor()

class Conf(list):
    """
    a dynamic configuration file represented as a list of sections

    where src is a file or a string
    """
    
    def __init__(self, src = None, caste = True, flavor = DEFAULT_CONF_FLAVOR):
        list.__init__(self)
        self.caste = caste
        self.flavor = flavor

        if isinstance(src, str):
            src = StringIO.StringIO(src)
        self.fp = src

        if self.fp:
            self.read()

    def __eq__(self, other):
        """unordered comparison"""
        if not isinstance(other, Conf):
            return False
        a = [s for s in other]
        b = [s for s in self]
        
        while a and b:
            av = a.pop()

            for i, bv in enumerate(b):
                if av == bv:
                    b.remove(v)
                    break
        return not a and not b
    
    def read(self):
        """read the configuration file"""
        while self: # clear
            self.pop()
        locked = True

        try:
            fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX)
        except (AttributeError, IOError):
            locked = False

        try:
            self.fp.seek(0, os.SEEK_END)
            size = self.fp.tell()
            self.fp.seek(0, os.SEEK_SET)
            
            while self.fp.tell() < size:
                section = Section(self.fp, self.caste, self.flavor)
                
                if not section.empty():
                    self.append(section)
        finally:
            if locked:
                try:
                    fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
                except (AttributeError, IOError):
                    pass
    
    def __str__(self):
        return "\n".join((str(s) for s in self))

    def sync(self):
        """synchronize data with the source"""
        self.fp.seek(0, os.SEEK_SET)
        
        for s in self:
            s.fp = self.fp # in case any sections were added
            s.sync()
            self.fp.write('\n') # trailing newline

class Section(dict):
    """a configuration file section"""
    
    def __init__(self, src = None, caste = True, flavor = DEFAULT_CONF_FLAVOR,
            title = None):
        self.caste = caste
        self.flavor = flavor

        if isinstance(src, str):
            src = StringIO.StringIO(src)
        self.fp = src
        self.title = title

        if self.fp:
            self.read()

    def add(self, key, value):
        """
        add a key/value pair to the configuration file

        the key may already exist
        """
        if self.has_key(key):
            if not isinstance(self[key], list):
                self[key] = [self[key]]
            self[key].append(value)
        else:
            self[key] = value

    def empty(self):
        """return whether there is a title or content"""
        return not len(self) and not self.titled()

    def __eq__(self, other):
        """unordered comparison"""
        if not isinstance(other, Section) \
                or not set(self.keys()) == set(other.keys()):
            return False

        for k, v in self.iteritems():
            if not other[k] == v:
                return False
        return self.title == other.title

    def read(self):
        """read the section"""
        locked = True
        read = 0

        try:
            fcntl.flock(self.fp.fileno(), fcntl.LOCK_EX)
        except (AttributeError, IOError):
            locked = False
        
        try:
            start = self.fp.tell()
            self.fp.seek(0, os.SEEK_END)
            size = self.fp.tell()
            self.fp.seek(start, os.SEEK_SET)
            
            while read < size:
                line = self.fp.readline()
                read += len(line)
                stripped = line.strip()

                if self.flavor.comment:
                    comment_index = stripped.find(self.flavor.comment)
                    
                    if comment_index > -1:
                        stripped = stripped[:comment_index]
                
                if not stripped:
                    continue
                elif self.flavor.title_end and self.flavor.title_start \
                        and stripped.startswith(self.flavor.title_start) \
                        and stripped.endswith(self.flavor.title_end) \
                        and len(stripped) >= len(self.flavor.title_end) \
                            + len(self.flavor.title_start): # title
                    if len(self) or self.titled(): # overstepped
                        self.fp.seek(-len(line), os.SEEK_CUR) # rectify
                        break
                    self.title = stripped[len(self.flavor.title_start)
                        :-len(self.flavor.title_end)]
                else:
                    k = stripped
                    v = None

                    if self.flavor.assignment \
                            and self.flavor.assignment in stripped:
                        k, v = [e.strip()
                            for e in stripped.split(self.flavor.assignment, 1)]

                        if self.caste:
                            v = guess_type(v)(v) # caste, if possible
                    self[k] = v
        finally:
            if locked:
                try:
                    fcntl.flock(self.fp.fileno(), fcntl.LOCK_UN)
                except (AttributeError, IOError):
                    pass

    def __str__(self):
        lines = []

        if self.titled():
            lines.append("".join((self.flavor.title_start, str(self.title),
                self.flavor.title_end)))

        for k, v in sorted(self.iteritems(), key = lambda e: e[0]):
            if v == None: # omit assignment
                lines.append(k)
            elif not isinstance(v, list):
                v = [v]

            for _v in v:
                lines.append(self.flavor.assignment.join(str(e)
                    for e in (k, _v)))

        if len(lines) > 1:
            lines.append("") # add a trailing newline
        return '\n'.join(lines)

    def sync(self):
        """synchronize data with the source"""
        self.fp.write(str(self))

    def titled(self):
        """return whether a title is present"""
        return not self.title == None
