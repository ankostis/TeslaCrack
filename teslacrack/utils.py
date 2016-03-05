# This is part of TeslaCrack.
#
# Copyright (C) 2016 Googulator
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
#
## Generic utils.
from __future__ import print_function, unicode_literals, division

from boltons.setutils import IndexedSet
from collections import UserDict

def longest_prefix_in_word(word, prefixlist):
    """
    >>> longest_prefix_in_word('abcd', ['ab','def', 'abc', 'abc'])
    'abc'
    >>> longest_prefix_in_word('', ['ab','def']) is None
    True

    """
    wl = [prefix for prefix in IndexedSet(prefixlist) if word.startswith(prefix)]
    if wl:
        return max(wl, key=len)


def _safe_startswith(o, prefix):
    try:
        return o.startswith(prefix)
    except Exception:
        pass

def words_with_prefix(prefix, wordlist):
    """
    >>> words_with_prefix('ab', ['ab','def', 'abc', 'abc'])
    ['ab', 'abc']
    >>> words_with_prefix('', list('abbbccc')) == list('abc')
    True
    """
    return [w for w in IndexedSet(wordlist)
            if w == prefix or _safe_startswith(w, prefix)]


def words_with_substr(substr, wordlist):
    """
    >>> words_with_substr('bc', ['ab','def', 'abc', 'abc'])
    ['abc']
    >>> words_with_substr('', list('abbcccc')) == list('abc')
    True
    """
    return [n for n in IndexedSet(wordlist) if substr in n]


class Item2Attr(object):
    """Mixin that can dress a NamedTuple as a dictionary."""

    __slots__ = ()

    def __getitem__(self, key):
        return getattr(self, key)

class MatchingDict(object):
    """
    Extra methods accessing matched dict-keys, optionally failing of none or more matched.

    - Use the ``XXXall()`` or :method:`containany` methods to return/act-upon a list
      of matched items; they may return/act-upon an empty list.
    - Use the ``XXXone()`` methods to return/act-upon a matched single item
      or fail otherwise.
    """

    def __init__(self, matchfunc, conv=None):
        self._matchfunc = matchfunc
        self._conv = conv

    def matchOne(self, prefix, default=None):
        if self._conv:
            prefix = self._conv(prefix)
        if prefix in self:
            key = prefix
        else:
            mkeys = self._matchfunc(prefix, self)
            if len(mkeys) != 1:
                raise KeyError('Prefix %r matched %i items: %r' %
                        (prefix, len(mkeys), mkeys))
            key = mkeys[0]
        return self[key]

    def delMatched(self, prefix):
        if self._conv:
            prefix = self._conv(prefix)
        if prefix in self:
            key = prefix
        else:
            mkeys = self._matchfunc(prefix, self)
            if len(mkeys) != 1:
                raise KeyError('Prefix %r matched %i keys: \n  %s' %
                        (prefix, len(mkeys), '\n  '.join(mkeys)))
            key = mkeys[0]
        del self[key]

    def containsMatched(self, prefix):
        if self._conv:
            prefix = self._conv(prefix)
        return any(self._matchfunc(prefix, self))

    def matchAll(self, prefix):
        if self._conv:
            prefix = self._conv(prefix)
        return [(mkey, self[mkey])
                for mkey in self._matchfunc(prefix, self)]

    def delAll(self, prefix):
        if self._conv:
            prefix = self._conv(prefix)
        mkeys = self._matchfunc(prefix, self)
        for mkey in mkeys:
            del self[mkey]
        return len(mkeys)

class ConvertingKDict(object):
    """Mixin for converting dict-KEYS - clients must ensure conversions on construction."""

    def __init__(self, conv):
        self._kconv = conv

    def __getitem__(self, key):
        ckey = self._kconv(key)
        return super(ConvertingKDict, self).__getitem__(ckey)
    def __setitem__(self, key, item):
        ckey = self._kconv(key)
        super(ConvertingKDict, self).__setitem__(ckey, item)
    def __delitem__(self, key):
        ckey = self._kconv(key)
        super(ConvertingKDict, self).__delitem__(ckey)
    def __contains__(self, key):
        ckey = self._kconv(key)
        return super(ConvertingKDict, self).__contains__(ckey)


class ConvertingVDict(object):
    """Mixin for converting dict-VALUES - clients must ensure conversions on construction."""

    def __init__(self, conv):
        self._vconv = conv

    def __setitem__(self, key, item):
        citem = self._vconv(item)
        super(ConvertingVDict, self).__setitem__(key, citem)


