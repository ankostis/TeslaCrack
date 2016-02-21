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
from __future__ import unicode_literals

from base64 import b64decode as b64dec, b64encode as b64enc
from binascii import hexlify, unhexlify
import codecs
from collections import defaultdict
from collections import namedtuple
import re
import struct

from future.builtins import str, int, bytes
from . import CrackException, log


def zipdict(*dcts):
    ## Utility from http://stackoverflow.com/questions/16458340/python-equivalent-of-zip-for-dictionaries
    if dcts:
        for k in set(dcts[0]).intersection(*dcts[1:]):
            yield k, tuple(d[k] for d in dcts)


def fix_int_key(int_key):
    return _lrotate_byte_key(unhexlify('%064x' % int_key))


def fix_hex_key(hex_bkey):
    # XXX: rstrip byte-or-str depends on type(aes-decrypted-key) in decrypt.known_AES_keys.
    return _lrotate_byte_key(unhexlify(hex_bkey.rstrip(b'\0')))

_unquote_str_regex = re.compile('^(?:[bu]?(?P<quote>[\'"]))(.*)(?P=quote)$')

def autoconvert_key_to_binary(d):
    """Returns bytes after trying various transforms on the v."""
    res = None
    try:
        if isinstance(d, int):
            res = ('int', lambda v: unhexlify('%x' % v))
        else:
            if len(res) >= 30: # Less probable all-number hexs assumed as ints.
                return res
            if isinstance(d, bytes):
                funcs = [('int', lambda v: unhexlify('%x' % int(v))),
                         ('hex', lambda v: unhexlify('%x' % int(v, 16))), #0x prefixed
                         ('xhex', unhexlify),
                         ('asc', b64dec),
                         ('bin', lambda v: codecs.raw_unicode_escape_encode(v)[0]), ]
            for conv, f in funcs:
                try:
                    res = conv, f(d)
                    break
                except:
                    pass
        log.info("Assumed %s-data(%r) --> %r", res[0], d, b64enc(res[1]))
        return res
    except Exception as ex:
        log.warning('While guessing key-data: %r', ex)
    if not res:
        raise CrackException('Cannot autoconvert binary-v: %s' % d)


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


def _apply_trans_list(trans_list, v):
    """Pass value through multiple `trans` (must be iterable, empty allowed)."""
    for i, trans in enumerate(trans_list, 1):
        try:
            v = trans(v)
        except Exception as ex:
            raise ValueError("Number %i trans(%r) on %r failed due to: %r!" % (
                    i, trans, v, ex))
    return v


def _convert_fields(field_values, field_trans_lists):
    """Applies any ``field_trans_lists := {field-->trans_list}`` on matching `field_values`."""
    ## Not as dict-comprehension to report errors.
    m = {}
    for fld, (v, trans_list) in zipdict(field_values, field_trans_lists):
        try:
            m[fld] = _apply_trans_list(trans_list, v)
        except ValueError as ex:
            raise ValueError("While converting header-field(%s=%r): %s!" % (
                                fld, v, ex))
    return m


Header = namedtuple('Header', 'start pub_btc priv_btc pub_aes priv_aes iv size')
_bin_fields = ['start', 'pub_btc', 'pub_aes', 'iv']
_hex_fields = ['priv_btc', 'priv_aes']
_header_fmt     = b'4s 65s 130s 65s 130s 16s 4s'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len


def _lrotate_byte_key(byte_key):
    while byte_key[0] == b'\0':
        byte_key = byte_key[1:] + b'\0'
    return byte_key

_x2b_fix_priv_key = lambda v: _lrotate_byte_key(unhexlify(v.rstrip(b'\0')))
_b2i = lambda v: struct.unpack('<I', v)[0]
_b2n = lambda v: int(hexlify(v), 16)
_b2s = lambda v: v.decode('ascii')
_b2x = lambda v: hexlify(v).decode('ascii')
_upp = lambda v: v.upper()
_0x = lambda v: '0x%s' % v
_i2h = lambda v: '0x%x'%v
_b2esc = lambda v: bytes(v)

#: See :func:`_hconvs_to_htrans()` for explanation.
_htrans_map = {name: _hconvs_to_htrans(hconv) for name, hconv in {
        'raw': [(_hex_fields+_bin_fields+['size'],      [bytes, _b2esc])],
        'fix': [(_hex_fields,           [_x2b_fix_priv_key, hexlify, _b2esc]),
                (_bin_fields,           [_b2esc]),
                (['size'],              [_b2i]), ],
        'bin': [(_hex_fields,           [_x2b_fix_priv_key, _b2esc]),
                (_bin_fields+['size'],  [_b2esc]), ],
        'xhex': [(_hex_fields,          [_x2b_fix_priv_key, _b2x, _upp]),
                 (_bin_fields+['size'], [_b2x, _upp]), ],
        'hex': [(_hex_fields,           [_x2b_fix_priv_key, _b2x, _0x]),
                (_bin_fields,           [_b2x, _0x]),
                (['size'],              [_b2i, _i2h]), ],
        'num': [(_hex_fields,           [_x2b_fix_priv_key, _b2n]),
                (_bin_fields,           [_b2n]),
                (['size'],              [_b2i]), ],
        '64':  [(_hex_fields,           [_x2b_fix_priv_key, b64enc, _b2s]),
                (_bin_fields,           [b64enc, _b2s]),
                (['size'],              [_b2i]), ],
    }.items()}


def _prefix_matched_hconv(hconv, hconvs=_htrans_map.keys()):
    matched_hconvs = [n for n in hconvs if hconv and n.startswith(hconv.lower())]
    if len(matched_hconvs) != 1:
        raise CrackException("Bad Header-conversion(%s)!"
                "\n  Must be a case-insensitive prefix of: %s"% (
                        hconv, sorted(_htrans_map.keys())))
    return matched_hconvs[0]

def convert_header(h, hconv):
    """
    Convert header fields into various formats.

    :param Header h:
    :param str hconv:
        any non-ambiguous case-insensitive *prefix* from:

          - raw: all bytes as-is - no conversion (i.e. hex private-keys NOT strip & l-rotate).
          - fix: like 'raw', but priv-keys fixed and size:int.
          - bin: all bytes (even private-keys), priv-keys: fixed.
          - xhex: all string-HEX, size:bytes-hexed.
          - hex: all string-hex prefixed with '0x', size: int-hexed.
          - num: all natural numbers, size: int.
          - 64: all base64, size(int) - most concise.
    """
    trans_map = _htrans_map[_prefix_matched_hconv(hconv)]
    fields_map = _convert_fields(h._asdict(), trans_map)
    return h._replace(**fields_map)
