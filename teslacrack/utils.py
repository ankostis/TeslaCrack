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


def prefixes_in_word(word, prefixlist):
    """Word `'abc'` is matched only by the 1st from ``['ab', 'bc', 'abcd', '']``"""
    return [prefix for prefix in prefixlist if word and word.startswith(prefix)]


def _safe_startswith(o, prefix):
    try:
        return o.startswith(prefix)
    except Exception:
        pass

def words_with_prefix(prefix, wordlist):
    """Word `'abc'` matches only the 3rd from  ``['ab', 'bc', 'abcd', '']``"""
    return [w for w in wordlist
            if w == prefix or _safe_startswith(w, prefix)]


def exact_or_words_with_prefix(prefix, wordlist):
    """Word `'abc'` matches only the 3rd from  ``['ab', 'bc', 'abcd', '']``"""
    l = []
    for w in wordlist:
        if w == prefix:
            return [prefix]
        if _safe_startswith(w, prefix):
            l.append(w)
    return l


def words_with_substr(substr, wordlist):
    return [n for n in wordlist if substr and substr in n]


class PrefixDictMixin(object):

    __slots__ = ()

    def __getitem__(self, prefix):
        mkeys = exact_or_words_with_prefix(prefix, self)
        if len(mkeys) != 1:
            raise KeyError('Prefix %r matched %i items!' % (prefix, len(mkeys)))
        return super(PrefixDictMixin, self).__getitem__(mkeys[0])

    def __delitem__(self, prefix):
        mkeys = exact_or_words_with_prefix(prefix, self)
        if len(mkeys) != 1:
            raise KeyError('Prefix %r matched %i keys: \n  %s' %
                    (prefix, len(mkeys), '\n  '.join(mkeys)))
        super(PrefixDictMixin, self).__delitem__(mkeys[0])

    def __contains__(self, prefix):
        return any(words_with_prefix(prefix, self))

    def getall(self, prefix):
        return [super(PrefixDictMixin, self).__getitem__(mkey)
                for mkey in words_with_prefix(prefix, self)]

    def delall(self, prefix):
        mkeys = words_with_prefix(prefix, self)
        for mkey in mkeys:
            super(PrefixDictMixin, self).__delitem__(mkey)
        return len(mkeys)


