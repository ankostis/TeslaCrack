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

from base64 import b64encode as b64enc
from binascii import hexlify, unhexlify
from collections import defaultdict
from collections import namedtuple
import struct

from future.builtins import str, int, bytes  # @UnusedImport

from . import CrackException


tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']


Header = namedtuple('Header', 'start pub_btc priv_btc pub_aes priv_aes iv size')
_header_fmt     = b'=5s 64s 130s 65s 130s 16s 1I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len


def zipdict(*dcts):
    ## Utility from http://stackoverflow.com/questions/16458340/python-equivalent-of-zip-for-dictionaries
    if dcts:
        for k in set(dcts[0]).intersection(*dcts[1:]):
            yield k, tuple(d[k] for d in dcts)


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
    """Pipes value through multiple `trans` (must be iterable, empty allowed)."""
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


_bin_fields = ['start', 'pub_btc', 'pub_aes', 'iv']
_hex_fields = ['priv_btc', 'priv_aes']


def _lrotate_byte_key(byte_key):
    while byte_key[0] == 0:
        byte_key = byte_key[1:] + b'\0'
    return byte_key


def fix_int_key(int_key):
    return _lrotate_byte_key(unhexlify('%064x' % int_key))

def fix_hex_key(hex_bkey):
    # XXX: rstrip byte-or-str depends on type(aes-decrypted-key) in decrypt.known_AES_keys.
    return _lrotate_byte_key(unhexlify(hex_bkey.rstrip(b'\0')))

_i2b = lambda v: struct.pack('<I', v)
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
        'raw': [(_hex_fields+_bin_fields,   [bytes, _b2esc]),
                (['size'],              [_i2b, _b2esc]), ],
        'fix': [(_hex_fields,           [fix_hex_key, hexlify, _b2esc]),
                (_bin_fields,           [_b2esc]), ],
        'bin': [(_hex_fields,           [fix_hex_key, _b2esc]),
                (_bin_fields,           [_b2esc]),
                (['size'],              [_i2b, _b2esc])],
        'xhex': [(_hex_fields,          [fix_hex_key, _b2x, _upp]),
                 (_bin_fields,          [_b2x, _upp]),
                 (['size'],             [_i2b, _b2x, _upp])],
        'hex': [(_hex_fields,           [fix_hex_key, _b2x, _0x]),
                (_bin_fields,           [_b2x, _0x]),
                (['size'],              [_i2h]), ],
        'num': [(_hex_fields,           [fix_hex_key, _b2n]),
                (_bin_fields,           [_b2n]), ],
        '64':  [(_hex_fields,           [fix_hex_key, b64enc, _b2s]),
                (_bin_fields,           [b64enc, _b2s]), ],
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


def parse_tesla_header(fd, hconv='64'):
    """
    Reads a tesla-file's header, checks its validity and converts.

    :param fd:
        a file-descriptor freshly opened in binary mode on a tesla-file.
    :param str hconv:
        what transform to apply (see func:`key.convert_header()`).
    :return:
        a :data:`Header` named-tuple
    """
    hbytes = fd.read(_header_len)
    magic_ok = any(hbytes.startswith(tmg) for tmg in tesla_magics)
    headerlen_ok = len(hbytes) >= _header_len
    if not (headerlen_ok and magic_ok):
        raise CrackException("File(%r) doesn't appear to be TeslaCrypted! "
                "\n  magic-bytes(%r) OK? %s, file-size(%i, minimum: %i) OK? %s." % (
                        getattr(fd, 'name', '<unknown>'),
                        bytes(hbytes[:5]), magic_ok,
                        len(hbytes), _header_len, headerlen_ok))
    h = Header._make(struct.unpack(_header_fmt, hbytes))
    return convert_header(h, hconv)
