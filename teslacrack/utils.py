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


def words_with_substr(substr, wordlist):
    """
    >>> words_with_substr('bc', ['ab','def', 'abc', 'abc'])
    ['abc']
    >>> words_with_substr('', list('abbcccc')) == list('abc')
    True
    """
    return [n for n in IndexedSet(wordlist) if substr in n]

