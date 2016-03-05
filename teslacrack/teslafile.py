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
## Parse keys from tesla-files headers, impl `file` sub-cmd.
from __future__ import print_function, unicode_literals, division

from base64 import b64encode
from binascii import hexlify
from collections import defaultdict, namedtuple
import struct

from future.builtins import str, int, bytes  # @UnusedImport

import itertools as itt

from . import CrackException, repr_conv, utils
from .keyconv import AKey
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

_header_fmt     = b'=5s 64s 130s 1x 64s 130s 16s 1I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len

_bin_fields = ('start', 'btc_pub_key', 'aes_pub_key', 'iv')
_hex_fields = ('btc_mul_key', 'aes_mul_key')

_Header = namedtuple('_Header',
        'start  btc_pub_key  btc_mul_key  aes_pub_key  aes_mul_key  iv  size')

#class Header(utils.Item2Attr, utils.MatchingDict, _Header):
class Header(_Header, utils.MatchingDict):
    """
    Immutable teslafile header-fields converted to AKey instances.

    Use :method:`from_fd()` to construct it.
    """
    @classmethod
    def from_fd(cls, fd, conv=None):
        """
        Reads a tesla-file's header, checks its validity and converts.

        :param fd:
                a file-descriptor freshly opened in binary mode on a tesla-file.
        :param str conv:
                the default feild-conversions (see :class:`AKey`).
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
            raw = cls._make(struct.unpack(_header_fmt, hbytes))
            h = raw._replace(
                    btc_pub_key=AKey.auto(raw.btc_pub_key, conv),
                    btc_mul_key=AKey.auto(tesla_mul_to_bytes(raw.btc_mul_key), conv),
                    aes_pub_key=AKey.auto(raw.aes_pub_key, conv),
                    aes_mul_key=AKey.auto(tesla_mul_to_bytes(raw.aes_mul_key), conv)
                    )
            h.raw = raw
        except Exception as ex:
            raise CrackException("Tesla-file(%r)'s keys might be corrupted: %s" %
                    (fname(), ex))
        return h

    def __init__(self, *args, **kwds):
        utils.MatchingDict.__init__(self, utils.words_with_substr)
        print(self)

    def __repr__(self):
        return '\n'.join('%15.15s: %r' % (k, v)
                for k, v in self._asdict().items())

