#! python
# -*- coding: UTF-8 -*-
#
# This is part of TeslaCrack..
#
# Copyright (C) 2016 Googulator
#
# TeslaCrack is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# TeslaCrack is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with TeslaCrack; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
from __future__ import unicode_literals

from Crypto.Cipher import AES  # @UnresolvedImport
import ecdsa

import functools as ft
import operator as op

from . import CrackException, log
from .key import fix_int_key
from .teslafile import check_tesla_file


def validate_primes(str_factors, expected_product=None):
    factors = [int(p) for p in str_factors]
    for i, f in enumerate(factors):
        if f >= 1<<256:
            raise CrackException("Factor no%i too large(%i bits): %s" %
                    (i, f.bit_length(), f))
    return factors


def product(factors):
    return ft.reduce(op.mul, factors)


def _validate_factors_product(factors, expected_product=None, allow_cofactor=False):
    """Check bitlen product-of-factors and add any cofactor remaining from `expected_product` (or scream)."""
    prod = product(factors)
    bitlen = prod.bit_length()
    if bitlen > 512:
        raise CrackException("Product-of-factors too big (%i bits)!" % bitlen)
    if expected_product:
        if prod > expected_product:
            raise CrackException("Extra factors given!")
        if prod % expected_product != 0:
            raise CrackException("Factors do not divide key, bad factors given!")
        cofactor = expected_product // prod
        if cofactor != 1:
            msg = "Incomplete factorization, found cofactor: %d" % cofactor
            if allow_cofactor:
                factors.append(cofactor)
                log.warning(msg)
            else:
                raise CrackException(msg)
    return sorted(factors)


def _gen_product_combinations(factors):
    """Yields the product of all factor-combinations fitting in 256 bits."""
    grand_prod = product(factors)
    prods = set()
    for i in range((1<<len(factors))-1, 1, -1):
        prod = product(f for j, f in enumerate(factors) if i & 1<<j)
        if (prod.bit_length() <= 256 and
                (grand_prod//prod).bit_length() <= 256 and
                prod not in prods):
            prods.add(prod)
            yield prod


def _guess_key(primes, key_ok_predicate):
    """Returns the 1st key satisfying the predicate, or None."""
    for key in _gen_product_combinations(primes):
        if key_ok_predicate(key):
            return key


def _guess_all_keys(primes, key_ok_predicate):
    """Returns the 1st or all candidate keys satisfying the predicate, or None."""
    keys = set()
    for key in _gen_product_combinations(primes):
        if key not in keys and key_ok_predicate(key):
            keys.add(key)
    if keys:
        return list(keys)


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

def _is_known_file(fname, fbytes):
    for ext, magic_bytes in known_file_magics.items():
        if '.%s.' % ext in fname.lower() and fbytes.startswith(magic_bytes):
            return True


def guess_aes_keys_from_file(fpath, primes):
    with open(fpath, "rb") as f:
        header = f.read(414)
        check_tesla_file(fpath, header[:5])
        aes_crypted_key = int(header[0x108:0x188].rstrip(b'\0'), 16)
        init_vector = header[0x18a:0x19a]
        data = f.read(16)
    primes = _validate_factors_product(primes, aes_crypted_key, allow_cofactor=True)

    def did_AES_produced_known_file(aes_key):
        file_bytes = AES.new(fix_int_key(aes_key), AES.MODE_CBC, init_vector).decrypt(data)
        return _is_known_file(fpath, file_bytes)

    return _guess_all_keys(primes, key_ok_predicate=did_AES_produced_known_file)


def guess_btc_key_from_btc_address(btc_address, primes, public_btc=None):
    try:
        from pybitcoin.keypair import BitcoinKeypair
    except ImportError:
        from coinkit.keypair import BitcoinKeypair

    primes = _validate_factors_product(primes, public_btc, allow_cofactor=True)

    def does_key_gen_my_btc_address(btc_key):
        test_addr = BitcoinKeypair(btc_key).address()
        return test_addr == btc_address

    return _guess_key(primes, key_ok_predicate=does_key_gen_my_btc_address)


def guess_ecdsa_key(ecdsa_secret, key, primes):
    primes = _validate_factors_product(primes, key, allow_cofactor=True)

    def does_key_gen_my_ecdsa(key):
        gen_ecdsa = ecdsa.SigningKey.from_secret_exponent(key,
                curve=ecdsa.SECP256k1).verifying_key.to_string()
        return ecdsa_secret.startswith(gen_ecdsa)

    return _guess_key(primes, key_ok_predicate=does_key_gen_my_ecdsa)


def _decide_which_key(primes, pub_aes, pub_btc, file):
    primes = _validate_factors_product(primes)
    prod = product(primes)
    is_aes = prod % pub_aes == 0
    is_btc = prod % pub_btc == 0
    if not (is_aes ^ is_btc):
        raise CrackException("Factors divide both or none AES and BTC public-keys!"
                "\n  Either too few factors or bad factors given."
                "\n  AES(divide=%s): %s\n  BTC(divide=%s): %s",
                is_aes, pub_aes, is_btc, pub_btc)
    if is_aes:
        key_name = 'AES'
        pub_key = pub_aes
    else:
        key_name = 'BTC'
        pub_key = pub_btc
    cofactor = pub_key // prod
    if cofactor != 1:
        primes.append(cofactor)
        log.warning("Incomplete factorization for %s public-key on file(%s), found cofactor(%d)!",
                key_name, file, cofactor)
    else:
        log.info("Guessing %s public-key on file(%s): \n  %s",
                key_name, file, pub_key)
    return sorted(primes), key_name


def guess_ecdsa_key_from_file(file, primes):
    with open(file, "rb") as f:
        header = f.read(414)
    check_tesla_file(file, header[:5])
    pub_aes = int(header[0x108:0x188].rstrip(b'\0'), 16)
    ecdsa_aes = header[200:265]
    pub_btc = int(header[0x45:0xc5].rstrip(b'\0'), 16)
    ecdsa_btc = header[5:70]

    primes, key_name = _decide_which_key(primes, pub_aes, pub_btc, file)

    def does_key_gen_my_ecdsa(key):
        gen_ecdsa = ecdsa.SigningKey.from_secret_exponent(key,
                curve=ecdsa.SECP256k1).verifying_key.to_string()
        return ecdsa_aes.startswith(gen_ecdsa) or ecdsa_btc.startswith(gen_ecdsa)

    key = _guess_key(primes, key_ok_predicate=does_key_gen_my_ecdsa)
    if key:
        return key_name, key
