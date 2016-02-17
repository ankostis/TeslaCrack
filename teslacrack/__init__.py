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
import base64
import binascii
import codecs
import logging
import re
import functools as ft
import operator as op


__version__ = '0.2.0'
__updated__ = "2016-02-17 20:36:21"

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


def validate_primes(str_factors, expected_product=None):
    factors = [int(p) for p in str_factors]
    for i, f in enumerate(factors):
        if f >= 1<<256:
            raise CrackException("Factor no%i too large(%i bits): %s" %
                    (i, f.bit_length(), f))
    return factors


def product(factors):
    return ft.reduce(op.mul, factors)


def validate_factors_product(factors, expected_product=None, allow_cofactor=False):
    """Check bitlen product-of-factors and add any cofactor remaining from `expected_product` (or scream)."""
    prod = product(factors)
    bitlen = prod.bit_length()
    if bitlen > 512:
        raise CrackException("Product-of-factors too big (%i bits)!" % bitlen)
    if expected_product:
        if prod > expected_product:
            raise CrackException("Extra factors given, or factorization was incorrect!")
        cofactor = expected_product // prod
        if cofactor != 1:
            msg = "Incomplete factorization, found cofactor: %d" % cofactor
            if allow_cofactor:
                factors.append(cofactor)
                log.warning(msg)
            else:
                raise CrackException(msg)
    return sorted(factors)


def gen_product_combinations(factors):
    """Yields the product of all factor-combinations fitting in 256 bits."""
    grand_prod = product(factors)
    prods = set()
    for i in range((1<<len(factors))-1, 1, -1):
        prod = product(f for j, f in enumerate(factors) if i & 1<<j)
        if (prod.bit_length() <= 256 and
                (grand_prod/prod).bit_length() <= 256 and
                prod not in prods):
            prods.add(prod)
            yield prod


def check_tesla_file(fpath, tesla_bytes):
    if tesla_bytes not in tesla_magics:
        raise CrackException(
                "File %s doesn't appear to be TeslaCrypted!" % fpath)
