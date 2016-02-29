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
"""Convert and parse keys to/from various formats (binary/hex/numeric, quoted, etc)."""
from __future__ import print_function, unicode_literals, division

from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
import re
import struct

from future.builtins import str, int, bytes  # @UnusedImport
from future.moves.collections import UserDict

from . import CrackException, log, repr_conv


###########################
### key-transformations ###
###########################
def i16(v): return int(v, 16)
def i2b(v): return bytes(struct.pack('<1I', v))
def b2n(v): return int(hexlify(v), 16)
def b2s(v): return v.decode('latin')
def b2x(v): return hexlify(v).decode('latin')
def upp(v): return v.upper()
def xs0x(v): return '0x%s' % v.lower()
def n2h(v): return '0x%x' % v


def _lalign_byte_key(byte_key):
    while byte_key[0] == 0:
        byte_key = byte_key[1:] + b'\0'
    return byte_key


def tesla_mul_to_bytes(hex_bkey):
    """Purposefully fails on odd-length keys, to detect corrupt tesla-headers."""
    return _lalign_byte_key(unhexlify(hex_bkey.rstrip(b'\0')))


def int_to_32or64bytes(int_key):
    """Teslacrypt uses 32byte AES keys & 64byte *mul* secrets."""
    nbits = int_key.bit_length()
    nbytes = nbits // 8 + bool(nbits % 8)
    hex_frmt = '%%0%ix' % (64 if nbytes <= 32 else 128)
    return _lalign_byte_key(unhexlify(hex_frmt % int_key))


def printable_key(v):
    """In PY2 bytes printed natively and grables console."""
    return repr(bytes(v)) if isinstance(v, bytes) else v


def str_or_byte(key):
    return bytes(key) if isinstance(key, bytes) else key.encode('latin')


def apply_trans_list(trans_list, v):
    """Pipes value through multiple `trans` (must be iterable, empty allowed)."""
    for i, trans in enumerate(trans_list, 1):
        try:
            v = trans(v)
        except Exception as ex:
            raise ValueError("Number %i trans(%r) on %r failed due to: %r!" % (
                    i, trans, v, ex))
    return v

##################################

_unquote_str_regex = re.compile('^(?:[bu]?(?P<quote>[\'"]))(.*)(?P=quote)$')
_unquote_byt_regex = re.compile(b'^(?:[bu]?(?P<quote>[\'"]))(.*)(?P=quote)$')

def _unquote(key):
    regex = _unquote_str_regex if isinstance(key, str) else _unquote_byt_regex
    m = regex.match(key)
    return m and m.group(2) or key


def autoconv_to_bytes(key):
    """Returns a tuple ``(<frmt-string>, <key-bytes>)`` after trying various transforms on the `key`."""
    res = None
    if isinstance(key, int):
        funcs = (('int', (int_to_32or64bytes, bytes)), )
    elif not isinstance(key, (bytes, str)):
            raise CrackException("Unknown key-type(%s) for key: %r", type(key), key)
    else:
        if len(key) < 30: # Less probable all-number hexs assumed as ints.
            raise CrackException('Soft Key-length(%i < 30) to autoconvert to binary: %s'
                    % (len(key), key))
        funcs = (('num',    (_unquote, int, int_to_32or64bytes, bytes)),
                 ('hex',    (_unquote, i16, int_to_32or64bytes, bytes)),
                 ('64',     (_unquote, b64decode, bytes)),
                 ('bin',    (_unquote, str_or_byte))
        )
    for conv, trans_list in funcs:
        try:
            res = conv, apply_trans_list(trans_list, key)
            break
        except:
            pass
    if res:
        log.debug("Assumed %s-data(%r) --> %r", res[0], key, b64encode(res[1]))
        return res[1]
    raise CrackException('Cannot autoconvert to binary: %s' % key)


class PairedKeys(UserDict):
    """A mutable registry of ``(kkey, vkey)`` pairs matching keys by various formats.

    Internally keys are converted to :attribute:`internal_conv` format
    for facilitating comparisons when debugging.
    """

    _trans_maps = {
        ##      FROM BYTES           TO_BYTES
        'bin':  ((lambda v: v, ),   (lambda v: v, )),
        'hex':  ((b2x, xs0x),       (i16, int_to_32or64bytes, bytes)),
        'num':  ((b2n,),            (int, int_to_32or64bytes, bytes)),
        '64':   ((b64encode, b2s),  (b64decode, bytes)),
    }

    # Controls internal storage and ``repr()`` of this instance.
    internal_conv = repr_conv

    def __init__(self, key_pairs=None):

        """
        :param dict key_pairs:
                key-pairs will be byte-converted by :func:`autoconv_to_bytes`.
        """
        pairs = key_pairs and {self._to_ifrmt(kkey): self._to_ifrmt(vkey)
                for kkey, vkey in key_pairs.items()}
        UserDict.__init__(self, dict=pairs)

    def _to_ifrmt(self, d, conv=None):
        if not conv:
            conv = self.internal_conv
        return apply_trans_list(self._trans_maps[conv][0], autoconv_to_bytes(d))

    def __getitem__(self, kkey):
        kkey = self._to_ifrmt(kkey)
        return self.data[kkey]

    def __setitem__(self, kkey, vkey):
        kkey = self._to_ifrmt(kkey)
        vkey = self._to_ifrmt(vkey)
        self.data[kkey] = vkey

    def __contains__(self, kkey):
        return self._to_ifrmt(kkey) in self.data

    def conv(self, kkey, conv):
        to_bytes = self._trans_maps[self.internal_conv][1]
        from_bytes = self._trans_maps[conv][0]
        return apply_trans_list(to_bytes + from_bytes, self[kkey])

    def __repr__(self):
        return '\n'.join('%s: %s' % (self._to_ifrmt(k), self._to_ifrmt(v))
                for k, v in self.items())
