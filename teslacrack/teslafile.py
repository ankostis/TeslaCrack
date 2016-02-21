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

from collections import namedtuple
import struct

from future.builtins import bytes

from . import CrackException, key as tckey


tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']


Header = namedtuple('Header', 'start pub_btc priv_btc pub_aes priv_aes iv size')
_header_fmt     = b'4s 65s 130s 65s 130s 16s 4s'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len


def check_tesla_file(fpath, tesla_bytes): #TODO: Delete
    if tesla_bytes not in tesla_magics:
        raise CrackException(
                "File %s doesn't appear to be TeslaCrypted!" % fpath)


def parse_tesla_header(fd, hconv='64'):
    hbytes = fd.read(_header_len)
    if len(hbytes) < _header_len or not any(hbytes.startswith(tmg) for tmg in tesla_magics):
        raise CrackException("File(%r) doesn't appear to be TeslaCrypted! "
                "\n  magic-bytes: %r, file-size: %i (minimum: %i)" % (
                getattr(fd, 'name', '<unknown>', bytes(hbytes[:5]), len(hbytes), _header_len)))
    h = Header._make(bytes(b) for b in struct.unpack(_header_fmt, hbytes))
    return tckey._convert_header(h, hconv)
