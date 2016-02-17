# This is part of TeslaCrack..
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

import logging

from Crypto.Cipher import AES  # @UnresolvedImport

from . import (CrackException, gen_product_combinations,
               validate_factors_product, fix_int_key, check_tesla_file)


known_file_magics = {
    'pdf': b'%PDF',
    'doc': b'\xd0\xcf\x11\xe0',
    'zip': 'PK', 'xlsx': b'PK', 'xlsmx': b'PK', 'docx': b'PK', 'odf': b'PK',
    'jpg': b'\xFF\xD8\xFF',
    'png': b'\x89PNG\r\n\x1A\n',
    'mp3': b'\x42\x4D',
    'gif': b'GIF89a', 'gif': b'GIF87a',
    'bz2': b'BZh', 'tbz2': b'BZh',
    'gz': b'\x1F\x8B', 'tgz': b'\x1F\x8B',
    '7z': b'7z\xBC\xAF\x27\x1C',
    'rar': b'Rar!\x1A\x07\x00',
}

log = logging.getLogger('unfactor')

def is_known_file(fname, fbytes):
    for ext, magic_bytes in known_file_magics.items():
        if '.%s.' % ext in fname.lower() and fbytes.startswith(magic_bytes):
            return True


def unfactor_aes_key(fpath, primes, aes_crypted_key, key_decryptor):
    primes = validate_factors_product(primes, aes_crypted_key, allow_cofactor=True)
    keys = set()
    for key in gen_product_combinations(primes):
        if is_known_file(fpath, key_decryptor(fix_int_key(key))):
            keys.add(key)
    if keys:
        return list(keys)
    raise CrackException("Failed reconstructing AES-key! "
            "\n  Re-validate your prime-factors and/or try with another file-type.")


def unfactor_aes_key_from_file(fpath, primes):
    with open(fpath, "rb") as f:
        header = f.read(414)
        check_tesla_file(fpath, header[:5])
        aes_crypted_key = int(header[0x108:0x188].rstrip(b'\0'), 16)
        init_vector = header[0x18a:0x19a]
        data = f.read(16)
    def aes_key_decryptor(aes_key):
        return AES.new(aes_key, AES.MODE_CBC, init_vector).decrypt(data)
    return unfactor_aes_key(fpath, primes, aes_crypted_key, aes_key_decryptor)
