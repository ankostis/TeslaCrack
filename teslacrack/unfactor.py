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
from __future__ import print_function, unicode_literals

import logging
import sys

from Crypto.Cipher import AES

from . import CrackException, fix_int_key, tesla_magics


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


def unfactor_key(fpath, primes, aes_crypted_key, key_decryptor):
    candidate_keys = set()
    prod = 1
    for i, p in enumerate(primes):
        if p >= 1<<256:
            raise CrackException("Factor no%i too large: %s" % (i, p))
        prod *= p

    if prod > aes_crypted_key:
        raise CrackException(
                "Extra factors given, or factorization was incorrect!")
    cofactor = aes_crypted_key // prod
    if cofactor * prod != aes_crypted_key:
        raise CrackException("Factors don't divide AES pubkey!")
    if cofactor != 1:
        log.warning("Incomplete factorization, found cofactor: %d", cofactor)

    found = False
    i = 1
    while i < 1<<len(primes):
        x = 1
        for j in range(len(primes)):
            if i & 1<<j:
                x *= int(primes[j])
        if (x < 1<<256 and aes_crypted_key//x < 1<<256 and
                is_known_file(fpath, key_decryptor(fix_int_key(x)))):
            candidate_keys.add('%064x' % x)
            found = True
        i += 1
    if cofactor != 1 and not found:
        i = 1
        while i < 1<<len(primes):
            x = cofactor
            for j in range(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if (x < 1<<256 and aes_crypted_key//x < 1<<256 and
                    is_known_file(fpath, key_decryptor(fix_int_key(x)))):
                candidate_keys.add(b'%064x' % x)
            i += 1
    if candidate_keys:
        return list(candidate_keys)
    raise CrackException("Failed reconstructing AES-key! "
            "\n  Ensure all factors are primes and/or try with another file-type.")


def unfactor_key_from_file(fpath, primes):
    with open(fpath, "rb") as f:
        header = f.read(414)
        if header[:5] not in tesla_magics:
            raise CrackException(
                    "File %s doesn't appear to be TeslaCrypted!", fpath)
        aes_crypted_key = int(header[0x108:0x188].rstrip(b'\0'), 16)
        init_vector = header[0x18a:0x19a]

        data = f.read(16)
        def aes_key_decryptor(aes_key):
            return AES.new(aes_key, AES.MODE_CBC, init_vector).decrypt(data)

        return unfactor_key(fpath, primes, aes_crypted_key, aes_key_decryptor)



def main(*args):
    """Parse args, setup logging and delegate to :func:`decrypt()`."""
    if not args:
        args = sys.argv

    log_level = logging.INFO
    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)
    log.debug('Args: %s', args)

    file = sys.argv[1]
    primes = [int(p) for p in sys.argv[2:]]
    log.info('Primes: \n  %s' % '\n  '.join(str(p) for p in primes))

    candidate_keys = unfactor_key_from_file(file, primes)
    print("Candidate AES private key: \n  %s" % '\n  '.join(candidate_keys))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor.py <sample file> <space-separated list of factors>")
        exit()
    try:
        print(main())
    except CrackException as ex:
        log.error("Reconstruction failed! %s", ex)
