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
"""Parse keys from tesla-files headers, impl `file` sub-cmd."""
from __future__ import unicode_literals

from base64 import b64encode
from binascii import hexlify
from collections import defaultdict, namedtuple
import struct

from future.builtins import str, int, bytes  # @UnusedImport

import itertools as itt

from . import CrackException, repr_conv
from .keyconv import (apply_trans_list, tesla_mul_to_bytes, b2x, b2n,
                  b2s, xs0x, upp, i2b, n2h)


def _hconvs_to_htrans(hconvs_map):
    """
    Restructs programmer-speced ordered `hconvs_map` to `htrans_map`, where::

        hconvs_map := [ ( match_field_list, trans_list ), ...]
        htrans := { field: trans_list }
    """
    htrans = defaultdict(list)
    for fields, trans in hconvs_map:
        for fld in fields:
            htrans[fld].extend(trans)
    return htrans


def _trans_per_field(trans_per_conv):
    return {name: _hconvs_to_htrans(hconv) for name, hconv in trans_per_conv.items()}


tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

_header_fmt     = b'=5s 64s 130s 65s 130s 16s 1I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len

_bin_fields = ('start', 'btc_ecdsa_key', 'aes_ecdsa_key', 'iv')
_hex_fields = ('btc_mul_key', 'aes_mul_key')


class Header(namedtuple('Header',
        'start  btc_ecdsa_key  btc_mul_key  aes_ecdsa_key  aes_mul_key  iv  size')):
    """
    Immutable Header-fields convertible to various formats.

    Available conversions:

      - raw: all bytes as-is - no conversion (i.e. hex mul-keys NOT strip & l-rotate).
      - fix: like 'raw', but mul-keys fixed and size:int; fail if mul-keys invalid.
      - bin: all bytes (even mul-keys), mul-keys: fixed.
      - xhex: all string-HEX, size:bytes-hexed.
      - hex: all string-hex prefixed with '0x', size: int-hexed.
      - num: all natural numbers, size: int.
      - 64: all base64, size(int) - most concise.
    """
    __slots__ = ()

    _trans_maps = _trans_per_field({
        'raw': ((_hex_fields+_bin_fields,   (bytes, )),
                (('size',),             (i2b, bytes))),
        'fix': ((_hex_fields,           (tesla_mul_to_bytes, hexlify, bytes)),
                (_bin_fields,           (bytes,))),
        'bin': ((_hex_fields,           (tesla_mul_to_bytes, bytes)),
                (_bin_fields,           (bytes,)),
                (('size',),             (i2b, bytes))),
        'xhex': ((_hex_fields,          (tesla_mul_to_bytes, b2x, upp)),
                 (_bin_fields,          (b2x, upp)),
                 (('size',),            (i2b, b2x, upp))),
        'hex': ((_hex_fields,           (tesla_mul_to_bytes, b2x, xs0x)),
                (_bin_fields,           (b2x, xs0x)),
                (('size',),             (n2h,))),
        'num': ((_hex_fields,           (tesla_mul_to_bytes, b2n)),
                (_bin_fields,           (b2n,))),
        '64':  ((_hex_fields,           (tesla_mul_to_bytes, b64encode, b2s)),
                (_bin_fields,           (b64encode, b2s))),
    })

    # Controls only the ``repr()`` of this instance.
    internal_conv = repr_conv

    @classmethod
    def from_fd(cls, fd):
        """
        Reads a tesla-file's header, checks its validity and converts.

        :param fd:
                a file-descriptor freshly opened in binary mode on a tesla-file.
        :param str hconv:
                what transform to apply (see :class:`Header`).
        :return:
            a :data:`Header` named-tuple
        """
        fname = lambda: getattr(fd, 'name', '<unknown>')
        hbytes = fd.read(_header_len)
        magic_ok = any(hbytes.startswith(tmg) for tmg in tesla_magics)
        headerlen_ok = len(hbytes) >= _header_len
        if not (headerlen_ok and magic_ok):
            raise CrackException("Tesla-file(%r) doesn't appear to be TeslaCrypted! "
                    "\n  magic-bytes(%r) OK? %s, file-size(%i, minimum: %i) OK? %s." % (
                            fname(),
                            bytes(hbytes[:5]), magic_ok,
                            len(hbytes), _header_len, headerlen_ok))
        try:
            h = cls._make(struct.unpack(_header_fmt, hbytes))
            ## To detect problems in the keys
            h.conv('btc_mul_key', 'fix')
            h.conv('aes_mul_key', 'fix')
        except Exception as ex:
            raise CrackException("Tesla-file(%r)'s keys might be corrupted: %s" %
                    (fname(), ex))
        return h

    def conv(self, fld, hconv):
        """
        Convert a header field into various formats.

        :param str fld:
            which field to convert
        :param str hconv:
            Any supported format, keys of :attribute:`_trans_maps`.
            See class docstring for explanation.
        """
        trans_map = self._trans_maps[hconv]
        return apply_trans_list(trans_map[fld], getattr(self, fld))

    def __repr__(self):
        return '\n'.join('%15.15s: %r' % (k, self.conv(k, self.internal_conv))
                for k in self._fields)


def _prefixes_in_word(word, prefixlist):
    """Word `'abc'` is matched only by the 1st from ``['ab', 'bc', 'abcd', '']``"""
    return [prefix for prefix in prefixlist if word and word.startswith(prefix)]


def _words_with_prefix(prefix, wordlist):
    """Word `'abc'` matches only the 3rd from  ``['ab', 'bc', 'abcd', '']``"""
    return [n for n in wordlist if prefix and n.startswith(prefix)]


def _words_with_substr(substr, wordlist):
    return [n for n in wordlist if substr and substr in n]


def match_header_conv(conv):
    """
    :param str conv:
        any non-ambiguous case-insensitive *prefix* from supported formats.
    """
    convs = Header._trans_maps.keys()
    matched_convs = _words_with_prefix(conv.lower(), convs)
    if len(matched_convs) != 1:
        raise CrackException("Bad Header-conversion(%s)!"
                "\n  Must be a case-insensitive prefix of: %s"% (
                        conv, sorted(convs)))
    return matched_convs[0]


def match_header_fields(field_substr_list):
    """An empty list matches all."""
    all_fields = Header._fields
    if not field_substr_list:
        fields_list = all_fields
    else:
        not_matched = [not _words_with_substr(f, all_fields) for f in field_substr_list]
        if any(not_matched):
            raise CrackException(
                    "Invalid header-field(s): %r! "
                    "\n  Must be a case-insensitive subs-string of: %s" %
                    ([f for f, m in zip(field_substr_list, not_matched) if m], all_fields))
        fields_list = [_words_with_substr(f, all_fields) for f in field_substr_list]
        fields_list = tuple(set(itt.chain(*fields_list)))
    return fields_list
