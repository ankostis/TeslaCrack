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

from binascii import unhexlify
from collections import namedtuple, OrderedDict
import struct

from future.builtins import str, int, bytes  # @UnusedImport
from toolz import dicttoolz

from . import CrackException, utils
from .keyconv import AKey, lalign_bytes


def tesla_mul_to_bytes(hex_bkey):
    """Purposefully fails on odd-length keys, to detect corrupt tesla-headers."""
    return lalign_bytes(unhexlify(hex_bkey.rstrip(b'\0')))


tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

_header_fmt     = b'=5s 64s 130s 1x 64s 130s 16s 1I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len

_bin_fields = ('start', 'btc_pub_key', 'aes_pub_key', 'iv')
_hex_fields = ('btc_mul_key', 'aes_mul_key')

_Header = namedtuple('_Header',
        'start  btc_pub_key  btc_mul_key  aes_pub_key  aes_mul_key  iv  size')

class Header(_Header):
    """
    Immutable teslafile header-fields converted to AKey instances.

    Use :method:`from_fd()` to construct it.
    """
    __slots__ = ()

    @classmethod
    def from_fd(cls, fd, conv=None, raw=False):
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
            h = cls._make(struct.unpack(_header_fmt, hbytes))
            if not raw:
                h = h._fix_raw(conv)
        except Exception as ex:
            raise CrackException("Tesla-file(%r)'s keys might be corrupted: %s" %
                    (fname(), ex))
        return h

    def __repr__(self):
        return '\n'.join('%15.15s: %r' % (k, v)
                for k, v in self._asdict().items())

    def __str__(self):
        return '\n'.join('%15.15s: %s' % (k, v)
                for k, v in self._asdict().items())

    def _fix_raw(self, conv=None):
        return self._replace(
            start=AKey(self.start, conv, _raw=1),
            btc_pub_key=AKey(self.btc_pub_key, conv, _raw=1),
            btc_mul_key=AKey(tesla_mul_to_bytes(self.btc_mul_key), conv, _raw=1),
            aes_pub_key=AKey(self.aes_pub_key, conv, _raw=1),
            aes_mul_key=AKey(tesla_mul_to_bytes(self.aes_mul_key), conv, _raw=1),
            iv=AKey(self.iv, conv, _raw=1),
        )


    def set_conv(self, conv):
        for f in self:
            if isinstance(f, AKey):
                AKey.dconv = conv


    def fields_by_substr_list(self, substr_list=()):
        """
        :rtype: OrderedDict
        """
        if not substr_list:
            return self._asdict()
        return dicttoolz.keyfilter(lambda k: any(ss in k for ss in substr_list),
                self._asdict(), OrderedDict)


def conv_header(h, conv):
    if isinstance(h, Header):
        h = h._asdict()
    return [(k, v.conv(conv) if k != 'size' else v)
            for k, v in h.items()]

