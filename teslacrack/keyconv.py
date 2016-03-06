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
## Convert and auto-parse keys to/from various formats (binary/hex/numeric, quoted, etc).
from __future__ import print_function, unicode_literals, division

from base64 import b64decode as b64dec, b64encode
from binascii import hexlify, unhexlify
import codecs
import logging
import math
import re
import struct

from future.builtins import str, int, bytes as newbytes  # @UnusedImport

import functools as ft
import future.utils as futils

from . import CrackException, repr_conv, utils


log = logging.getLogger(__name__)

###########################
### key-transformations ###
###########################
def i16(v): return int(v, 16)
def i2b(v): return newbytes(struct.pack('<1I', v))
def b2n(v): return int(hexlify(v), 16)
def b2s(v): return v.decode('latin')
def b2x(v): return hexlify(v).decode('latin')
def upp(v): return v.upper()
def xs0x(v): return '0x%s' % v.lower()  if v else ''
def n2h(v): return '0x%x' % v
def esc_bbytes_2b(v): return  codecs.escape_decode(v)[0]
def esc_sbytes_2b(v): return  codecs.escape_encode(v)[0]
def native(v): return v.__native__() if futils.PY2 else v

_hex_str_regex    = re.compile('^(?:0x)?([a-f0-9]+)$', re.I)
_hex_byt_regex    = re.compile(b'^(?:0x)?([a-f0-9]+)$', re.I)

def is_hex(v):
    return (_hex_byt_regex.match(v).group(1)
            if isinstance(v, newbytes) else
            _hex_str_regex.match(v).group(1))



if futils.PY2:
    _py2_base64_check_regex = re.compile('^[\w+/=]+$')
    def b64decode(v):
        _py2_base64_check_regex.match(v).groups
        return b64dec(v)
else:
    b64decode = ft.partial(b64dec, validate=True)


def lalign_bytes(byte_key):
    if any(byte_key):
        while byte_key[0] == 0:
            byte_key = byte_key[1:] + b'\0'
    return byte_key


def int_to_32or64bytes(int_key):
    """Teslacrypt uses 32byte AES keys & 64byte *mul* secrets."""
    nbytes = math.ceil(int_key.bit_length() / 8.0)
    hex_frmt = '%%0%ix' % (64 if nbytes <= 32 else 128)
    return lalign_bytes(unhexlify(hex_frmt % int_key))


def printable_key(v):
    """In PY2 bytes printed natively and grables console."""
    return repr(newbytes(v)) if isinstance(v, newbytes) else v


def s_or_b_2_bytes(key):
    return newbytes(key) if isinstance(key, newbytes) else newbytes(key.encode('latin'))


def apply_trans_list(trans_list, v):
    """Pipes value through multiple `trans` (must be iterable, empty allowed)."""
    for i, trans in enumerate(trans_list, 1):
        if trans:
            try:
                v = trans(v)
            except Exception as ex:
                raise ValueError("Number %i trans(%r) on %r failed due to: %r!"
                        % (i, trans, v, ex))
    return v

_unquote_str_regex    = re.compile('^(?:u?(?P<quote>[\'"]))(.*)(?P=quote)$')
_unquote_byt_regex    = re.compile(b'^(?:u?(?P<quote>[\'"]))(.*)(?P=quote)$')
_unquote_b_str_regex = re.compile('^(?:[bu]?(?P<quote>[\'"]))(.*)(?P=quote)$')
_unquote_b_byt_regex = re.compile(b'^(?:[bu]?(?P<quote>[\'"]))(.*)(?P=quote)$')

def _unquote_str(key, byt_regex, str_regex):
    try:
        regex = byt_regex if isinstance(key, newbytes) else str_regex
        m = regex.match(key)
        key = m and m.group(2) or key
    except:
        pass
    return key

_unquote = ft.partial(_unquote_str,
        byt_regex=_unquote_byt_regex, str_regex=_unquote_str_regex)
_unquote_bu = ft.partial(_unquote_str,
        byt_regex=_unquote_b_byt_regex, str_regex=_unquote_b_str_regex)

##################################

## The order is important:
#
_try_to_bytes_convs = (
    ('num',    (_unquote, int, int_to_32or64bytes, newbytes)),
    ('hex',    (_unquote, is_hex, unhexlify, newbytes)),
    ('asc',    (_unquote, b64decode, newbytes)),
    ('bin',    (_unquote_bu, esc_bbytes_2b, _unquote_bu, s_or_b_2_bytes)),
    ('bin',    (_unquote_bu, esc_sbytes_2b, _unquote_bu, s_or_b_2_bytes)),
    ('bin',    (_unquote_bu, s_or_b_2_bytes)),
)

_from_bytes_convs = {
    'bin':  (native, newbytes),
    'hex':  (b2x, xs0x, str),
    'num':  (b2n,),
    'asc':  (b64encode, b2s, str),
}

def _autoconv_to_bytes(key):
    """Auto-converts any data as newbytes, retaining their original format as string.

    Conversions described in :class:`AKey`.

    :param key: non-null
    :returns: a tuple ``(<frmt-string>, <key-bytes>)``."""
    res = None
    if isinstance(key, AKey):
        return (key._conv, newbytes(key))
    if isinstance(key, int):
        nbytes = math.ceil(key.bit_length() / 8.0)
        min_nbytes = 16
        if nbytes <= 16:
            log.warning('Suspiciously small integer(%i-bytes <= %i) to autoconvert to binary: %s',
                    nbytes, min_nbytes, key)
        res = ('num', newbytes(int_to_32or64bytes(key)))
    elif not isinstance(key, (newbytes, str)):
            raise CrackException("Unknown key-type(%s) for key: %r", type(key), key)
    else:
        min_len = 8
        if len(key) < min_len: # Less probable all-number hexs assumed as ints.
            log.warning('Short Key-length(%i < %i) to autoconvert to binary: %s',
                    len(key), min_len, key)
        for conv, trans_list  in _try_to_bytes_convs:
            try:
                res = conv, apply_trans_list(trans_list, key)
                break
            except:
                pass
    if res:
        log.debug("Assumed %s-data(%r) --> %r", res[0], key, res[1])
        return res
    raise CrackException('Cannot autoconvert to binary: %s' % key)


def _safe_autoconv(v):
    try:
        v = _autoconv_to_bytes(v)[1]
    except Exception:
        pass
    return v


def _convid(conv_prefix):
    convs = utils.words_with_prefix(conv_prefix, _from_bytes_convs)
    if len(convs) != 1:
        raise KeyError('Conversion-prefix %r not in %s!' %
                (conv_prefix, list(_from_bytes_convs)))
    return convs[0]


def conv_bytes(b, conv):
    if not conv:
        conv = repr_conv
    trans = _from_bytes_convs[_convid(conv)]
    return apply_trans_list(trans, b)



#class AKey(type(b'')):
class AKey(newbytes):
    """
    Bytes using a best-effort autoconversion from various formats utilized by TeslaCrack.

    Use :method:`auto()` to construct.

    - Consumes any ``b"`` or ``u"`` prefixes and quotings.
    - Integers converted to big-endian, left-aligned, 64 or 128 bytes.
    - Use :method:`conv()` or `bin, hex, num, asc` properties to switch formats.
    - The default conversion :attribute:`_conv` is set by the autoconversion,
      if not overridden on construction.
    - Keys must not be `None`.
    """

    @classmethod
    def auto(cls, key, conv=None):
        """
        :param _conv:
                default
        :type conv: str or None
        :param unparsed:
                enforces key-type - use it with caution, no check!
        :type _unparsed: bool or str
        """
        aconv, byts = _autoconv_to_bytes(key)
        return AKey.raw(byts, conv or aconv)

    @classmethod
    def raw(cls, key, conv=None):
        if futils.PY2 and type(key) == newbytes:
            ## WORKAROUND `newbytes` constructor PY3.3 "trik" which returns
            #    any `newbytes` as-is, instead of invoking ``super.__new__()``.
            key = key.__native__()
        ak = AKey(key)
        if conv:
            ak._conv = conv
        return ak

    _conv = None

    def conv(self, conv_prefix=None):
        return conv_bytes(self, conv_prefix or self._conv)

    def __repr__(self):
        me = self.conv()
        if me is self:
            me = newbytes(self) if futils.PY2 else newbytes(self) ## Avoid infinite recursion.
        if '_conv' not in vars(self):
            return 'AKey(%r)' % me
        return 'Akey(%r, %r)' % (me, self._conv)

    def __str__(self):
        return self.conv()

    @property
    def num(self): return self.conv('num')
    @property
    def bin(self): return self.conv('bin')
    @property
    def hex(self): return self.conv('hex')
    @property
    def asc(self): return self.conv('asc')

