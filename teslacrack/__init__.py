# This is part of TeslaCrack - decrypt files encrypted by TeslaCrypt ransomware.
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
import base64
import binascii
import codecs
import logging
import re


__version__ = '0.2.0'
__updated__ = "2016-02-07 23:51:27"

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


def lalign_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def fix_int_key(int_key):
    return lalign_key(binascii.unhexlify('%064x' % int_key))


def fix_hex_key(hex_key):
    return lalign_key(binascii.unhexlify(hex_key))


def guess_binary(data):
    """Returns bytes after trying various transforms on the data."""
    if isinstance(data, bytes):
        funcs = [binascii.unhexlify, base64.b64decode, lambda d: d]
    else:
        funcs = [lambda d: binascii.unhexlify('%x' % int(d)),
                 binascii.unhexlify, base64.b64decode,
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

