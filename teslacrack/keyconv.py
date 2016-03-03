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
import math
import re
import struct

from future.builtins import str, int, bytes  # @UnusedImport

import functools as ft
import future.utils as futils

from . import CrackException, log, repr_conv, utils


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
def esc_bbytes_2b(v): return  codecs.escape_decode(v)[0]
def esc_sbytes_2b(v): return  codecs.escape_encode(v)[0]

if futils.PY2:
    _py2_base64_check_regex = re.compile('^[\w+/=]+$')
    def b64decode(v):
        _py2_base64_check_regex.match(v).groups
        return b64dec(v)
else:
    b64decode = ft.partial(b64dec, validate=True)


def _lalign_byte_key(byte_key):
    while byte_key[0] == 0:
        byte_key = byte_key[1:] + b'\0'
    return byte_key


def tesla_mul_to_bytes(hex_bkey):
    """Purposefully fails on odd-length keys, to detect corrupt tesla-headers."""
    return _lalign_byte_key(unhexlify(hex_bkey.rstrip(b'\0')))


def int_to_32or64bytes(int_key):
    """Teslacrypt uses 32byte AES keys & 64byte *mul* secrets."""
    nbytes = math.ceil(int_key.bit_length() / 8.0)
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
        regex = byt_regex if isinstance(key, bytes) else str_regex
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
    ('num',    (_unquote, int, int_to_32or64bytes, bytes)),
    ('hex',    (_unquote, i16, int_to_32or64bytes, bytes)),
    ('asc',    (_unquote, b64decode, bytes)),
    ('bin',    (_unquote_bu, esc_bbytes_2b, _unquote_bu, str_or_byte)),
    ('bin',    (_unquote_bu, esc_sbytes_2b, _unquote_bu, str_or_byte)),
    ('bin',    (_unquote_bu, str_or_byte)),
)

_from_bytes_convs = {
    'bin':  (None, ),
    'hex':  (b2x, xs0x),
    'num':  (b2n,),
    'asc':  (b64encode, b2s),
}

def _autoconv_to_bytes(key):
    """Auto-converts any data as bytes, retaining their original format as string.

    Conversions described in :class:`AKey`.

    :param key: non-null
    :returns: a tuple ``(<frmt-string>, <key-bytes>)``."""
    res = None
    if isinstance(key, AKey):
        res = (key.dconv, key._key)
    elif isinstance(key, int):
        nbytes = math.ceil(key.bit_length() / 8.0)
        min_nbytes = 16
        if nbytes <= 16:
            log.warning('Suspiciously small integer(%i-bytes <= %i) to autoconvert to binary: %s',
                    nbytes, min_nbytes, key)
        res = ('num', bytes(int_to_32or64bytes(key)))
    elif not isinstance(key, (bytes, str)):
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
    trans = _from_bytes_convs[_convid(conv)]
    return apply_trans_list(trans, b)


class AKey(object):
    """
    AutoKeys stored internally in bytes.

    - Consumes any ``b"`` or ``u"`` prefixes and quotings.
    - Integers converted to big-endian, left-aligned, 64 or 128 bytes.
    - Use ``int(ak)`` or ``bytes(ak)`` for the most common formats,
      or :method:`conv()` mthod.
    - The default conversion :attribute:`dconv` is set by the autoconversion,
      if not overridden on construction.
    - Keys must not be `None`.
    """
    dconv = repr_conv

    def __init__(self, key, conv=None, unparsed=False):
        """
            :param dconv:
                    default
            :type dconv: str or None
            :param unparsed:
                    enforces key-type - use it with caution, no check!
            :type unparsed: bool or str

        """
        aconv, self._key = _autoconv_to_bytes(key)
        log.debug("Assumed %s-data(%r) --> %r", aconv, key, self._key)
        self.dconv = conv or aconv

    def conv(self, conv_prefix):
        return conv_bytes(self._key, conv_prefix)

    def __bytes__(self):    return self._key

    def __int__(self):
        return self.conv('bin')

    def __eq__(self, o):
        if o is self:
            return True
        try:
            return o._key == self._key
        except Exception:
            return self._key == _safe_autoconv(o)

    def __hash__(self): return hash(self._key)

    def __repr__(self):
        me = self.conv(self.dconv)
        if 'dconv' not in vars(self):
            return '%s(%r)' % (type(self).__name__, me)
        return '%s(%s, %r)' % (type(self).__name__, me, self.dconv)

    def __str__(self):
        s = self.conv(self.dconv)
        if isinstance(s, bytes):
            s = '%r' % s
        return s

    def __len__(self):          return len(self._key)
    def __getitem__(self, i):   return self._key[i]
    def __iter__(self):         return iter(self._key)
    def __reversed__(self):     return reversed(self._key)

    def __contains__(self, v):
        return _safe_autoconv(v) in self._key
    def startswith(self, prefix):
        return self._key.startswith(_safe_autoconv(prefix))
    def enddswith(self, prefix):
        return self._key.startswith(_safe_autoconv(prefix))

    @property
    def num(self): return self.conv('num')
    @property
    def bin(self): return self.conv('bin')
    @property
    def hex(self): return self.conv('hex')
    @property
    def asc(self): return self.conv('asc')


class AKKDict(dict):
    """Mixin for dicts with :class:`AKey` KEYS - clients must ensure `AKeys` on construction."""

    __slots__ = ()

    def __getitem__(self, key):
        return super(AKKDict, self).__getitem__(_safe_autoconv(key))
    def __setitem__(self, key, item):
        super(AKKDict, self).__setitem__(_safe_autoconv(key), item)
    def __delitem__(self, key):
        super(AKKDict, self).__delitem__(_safe_autoconv(key))
    def __contains__(self, key):
        return super(AKKDict, self).__contains__(_safe_autoconv(key))


class AKVDict(dict):
    """Mixin for dicts with :class:`AKey` VALUES - clients must ensure `AKeys` on construction."""

    __slots__ = ()

    def __setitem__(self, key, item):
        super(AKVDict, self).__setitem__(key, _safe_autoconv(item))


class PairedKeys(AKVDict, AKKDict, utils.PrefixMatched, dict):
    """Mutable registry of ``(kkey, vkey)`` pairs matching keys by various formats. """

    __slots__ = ()

    def __init__(self, pairs_or_dict=(), **kwds):
        d = dict(pairs_or_dict, **kwds)
        super(PairedKeys, self).__init__((AKey(k), AKey(v)) for k, v in d.items())
