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


def exact_or_words_with_prefix(prefix, wordlist):
    """Word `'abc'` matches only the 3rd from  ``['ab', 'bc', 'abcd', '']``"""
    l = []
    for w in IndexedSet(wordlist):
        if w == prefix:
            return [prefix]
        if _safe_startswith(w, prefix):
            l.append(w)
    return l


def words_with_substr(substr, wordlist):
    """
    >>> words_with_substr('bc', ['ab','def', 'abc', 'abc'])
    ['abc']
    >>> words_with_substr('', list('abbcccc')) == list('abc')
    True
    """
    return [n for n in IndexedSet(wordlist) if substr and substr in n]


class Item2Attr(object):
    """Mixin that can dress a NamedTuple as a dictionary."""
    __slots__ = ()

    def __getitem__(self, key):
        return getattr(self, key)


class PrefixMatched(object):
    """
    Mixin for accessing dict-keys by their prefixes, and/or fail when none or more matched.

    - Use the ``XXXall()`` or :method:`containany` methods to return/act-upon a list
      of prefix-matched items; they may return/act-upon an empty list.
    - Use the ``XXXone()`` methods to return/act-upon a prefix-matched single item
      or fail otherwise.
    """
    __slots__ = ()

    def getone(self, prefix, default=None):
        mkeys = exact_or_words_with_prefix(prefix, self)
        if len(mkeys) != 1:
            raise KeyError('Prefix %r matched %i items!' % (prefix, len(mkeys)))
        return self[mkeys[0]]

    def delone(self, prefix):
        mkeys = exact_or_words_with_prefix(prefix, self)
        if len(mkeys) != 1:
            raise KeyError('Prefix %r matched %i keys: \n  %s' %
                    (prefix, len(mkeys), '\n  '.join(mkeys)))
        del self[mkeys[0]]

    def containsany(self, prefix):
        return any(words_with_prefix(prefix, self))

    def getall(self, prefix):
        return [self[mkey]
                for mkey in words_with_prefix(prefix, self)]

    def delall(self, prefix):
        mkeys = words_with_prefix(prefix, self)
        for mkey in mkeys:
            del self[mkey]
        return len(mkeys)
