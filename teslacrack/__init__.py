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

from binascii import hexlify, unhexlify
import codecs
from collections import defaultdict
from collections import namedtuple
import logging
import struct

from future.builtins import str, int

import base64 as b64

from ._version import __version__, __updated__


__title__ = "teslacrack"
__summary__ = "Decrypt files crypted by TeslaCrypt ransomware"
__uri__ = "https://github.com/Googulator/TeslaCrack"
__license__ = 'GNU General Public License v3 (GPLv3)'


class CrackException(Exception):
    pass


log = logging.getLogger('teslacrypt')

tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']


def init_logging(level=logging.INFO,
                 frmt="%(asctime)-15s:%(levelname)3.3s: %(message)s"):
    logging.basicConfig(level=level, format=frmt)



def fix_int_key(int_key):
    return _lrotate_byte_key(unhexlify(b'%064x' % int_key))


def fix_hex_key(hex_bkey):
    return _lrotate_byte_key(unhexlify(hex_bkey.rstrip(b'\0')))


def guess_binary(data):
    """Returns bytes after trying various transforms on the data."""
    if isinstance(data, bytes):
        funcs = [unhexlify, b64.b64decode, lambda d: d]
    else:
        funcs = [lambda d: unhexlify('%x' % int(d)),
                 unhexlify, b64.b64decode,
                 lambda d: codecs.raw_unicode_escape_encode(d)[0]]
    for f in funcs:
        try:
            res = f(data)
            log.debug("Guessed bin-data(%s) --> %s(%s)", data, f, res)
            if len(res) >= 8:
                return res
        except:
            pass
    raise ValueError('Cannot guess binary-data: %s' % data)


def check_tesla_file(fpath, tesla_bytes): #TODO: Delete
    if tesla_bytes not in tesla_magics:
        raise CrackException(
                "File %s doesn't appear to be TeslaCrypted!" % fpath)


Header = namedtuple('Header', 'pub_btc priv_btc pub_aes priv_aes iv size')
_header_fmt = b'<4x 65s 130s 65s 130s 16s I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len


def parse_tesla_header(fd):
    hbytes = fd.read(_header_len)
    if hbytes < _header_len or not any(hbytes.startswith(tmg) for tmg in tesla_magics):
        raise CrackException("File %s doesn't appear to be TeslaCrypted! \n  %s" %
                ("File-size less-than tesla-header size."
                if hbytes < _header_len
                else 'Bad tesla magic-bytes.', getattr(fd, 'name', '<unknown>')))
    return Header._make(struct.unpack(_header_fmt, hbytes))


def _hconvs_to_htrans(hconvs):
    """
    Restructs programmer-speced `hconvs` ordered-mapping to `htrans` mapping, where::

        hconvs := [ ( match_field_list, trans_list ), ...]
        htrans := { field: trans_list }
    """
    htrans = defaultdict(list)
    for fields, trans in hconvs:
        for fld in fields:
            htrans[fld].extend(trans)
    return htrans


def _apply_trans(v, trans_list):
    """Pass value through multiple `trans` (must be iterable, empty allowed)."""
    for trans in trans_list:
        v = trans(v)
    return v


def _apply_htrans(h, htrans):
    """Replaces Header-fields by applying ``htrans := {field-->trans_list}`` on matching fields."""
    return h._replace(**{fld: _apply_trans(v, htrans.get(fld, ()))
                         for fld, v in h._asdict().items()
                         if fld in htrans})


_bin_fields = ['pub_btc', 'pub_aes', 'iv']
_hex_fields = ['priv_btc', 'priv_aes']


def _lrotate_byte_key(byte_key):
    while byte_key[0] == b'\0':
        byte_key = byte_key[1:] + b'\0'
    return byte_key

_x2b_fix_priv_key = lambda v: _lrotate_byte_key(unhexlify(v.rstrip(b'\0')))
_b2s = lambda v: v.decode(encoding='ascii')
_b2e = lambda v: v#.decode('string-escape')
_b2i = lambda v: struct.unpack('<I', v)
_x2h = lambda v: '0x%s'%v
_blow = bytes.lower
_h2i = lambda v: int(v, 16)
_i2b = lambda v: int(v).to_bytes(4, byteorder='little')
_i2h = lambda v: '0x%x'%v
_i2d = lambda v: "{:,}".format(v)

#: See :func:`_hconvs_to_htrans()` for explanation.
_htrans = {name: _hconvs_to_htrans(hconv) for name, hconv in {
        'fix': [(_hex_fields, [_x2b_fix_priv_key, hexlify, _blow]),],
        'bin': [(_hex_fields, [_x2b_fix_priv_key, _b2e]),
                (_bin_fields, [_b2e]),
                (['size'], [_i2b, ]), ],
        'xhex': [
                (_hex_fields, [_x2b_fix_priv_key, hexlify, _blow]),
                (_bin_fields, [hexlify]),
                (['size'], [_i2b, hexlify]), ],
        'hex': [(_hex_fields, [_x2b_fix_priv_key, hexlify, _blow, _x2h]),
                (_bin_fields, [hexlify, _x2h]),
                (['size'], [_i2h]), ],
        'int': [(_hex_fields, [_x2b_fix_priv_key, hexlify, _h2i]),
                (_bin_fields, [hexlify, _h2i]), ],
        'asc': [(_hex_fields, [_x2b_fix_priv_key, b64.b64encode, _b2s]),
                (_bin_fields, [b64.b64encode, _b2s]),
                (['size'], [_i2d]), ],
        'raw':[],
    }.items()}

def hconv(h, hconv_name='fix'):
    """
    Convert header fields into various formats.

    :param Header h:
    :param str hconv_name:
        any non-ambiguous case-insensitive *prefix* from:

          - raw: no conversion, all bytes, but size:int, i.e. hex private-keys unfixed;
          - fix: (default) all bytes, but size:int, and fix priv-keys (strip & l-rotate);
          - bin: all bytes;
          - hex: all hex-strings, prefixed '0x' prefix;
          - xhex: hex-bytes, size:int's bytes hexified(!) - may fail if header bytes corrupted;
          - int: all integers;
          - asc: all base64, size(int, thousands grouped) - most concise;
    """
    names_matched = [n for n in _htrans if hconv_name and n.startswith(hconv_name)]
    if len(names_matched) != 1:
        raise CrackException("Bad Header-conversion(%s)!"
                "\n  Available conversions: %s"% (
                        hconv_name, _htrans.keys()))
    return _apply_htrans(h, _htrans[names_matched[0]])
