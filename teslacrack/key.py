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
from binascii import unhexlify
import codecs
import re

from future.builtins import str, int, bytes  # @UnusedImport

from . import CrackException, log


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

