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
import re
import struct

from future.builtins import str, int, bytes  # @UnusedImport

from . import CrackException, log


##################################
### key-transformation function ##
##################################
i16 = lambda v: int(v, 16)
n2b = lambda v: hexlify(v).decode('latin')
i2b = lambda v: struct.pack('<1I', v)
b2i = lambda v: struct.unpack('<1I', v)[0]
b2n = lambda v: int(hexlify(v), 16)
b2s = lambda v: v.decode('latin')
b2x = lambda v: hexlify(v).decode('latin')
upp = lambda v: v.upper()
xs0x = lambda v: '0x%s' % v
ns2h = lambda v: '0x%x' % v
nb2h = lambda v: b'0x%x' % v
b2esc = lambda v: bytes(v)
rstrip = lambda v: v.rstrip(b'\0')

def _lrotate_byte_key(byte_key):
    while byte_key[0] == 0:
        byte_key = byte_key[1:] + b'\0'
    return byte_key


def key_x2b(hex_bkey):
    # XXX: rstrip byte-or-str depends on type(aes-decrypted-key) in decrypt.known_AES_keys.
    return _lrotate_byte_key(unhexlify(hex_bkey))


def key_n2b(int_key):
    return _lrotate_byte_key(unhexlify('%064x' % int_key))


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


def autoconv_key(key):
    """Returns bytes after trying various transforms on the `key`."""
    res = None
    if isinstance(key, int):
        res = ('int', key_n2b(key))
    elif not isinstance(key, (bytes, str)):
            raise CrackException("Unknown key-type(%s) for key: %r", type(key), key)
    else:
        if len(key) < 30: # Less probable all-number hexs assumed as ints.
            raise CrackException('Soft Key-length(%i < 30) to autoconvert to binary: %s'
                    % (len(key), key))
        funcs = (('int',    (_unquote, int, key_n2b)),
                 ('hex',    (_unquote, i16, key_n2b)),
                 ('64',     (_unquote, b64dec)),
                 ('bin',    (_unquote, str_or_byte))
        )
        for conv, trans_list in funcs:
            try:
                res = conv, apply_trans_list(trans_list, key)
                break
            except:
                pass
    if res:
        log.info("Assumed %s-data(%r) --> %r", res[0], key, b64enc(res[1]))
        return res
    raise CrackException('Cannot autoconvert to binary: %s' % key)

