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
from __future__ import print_function, unicode_literals, division

import logging

from Crypto.Cipher import AES  # @UnresolvedImport
import ecdsa
from future.builtins import bytes
from pycoin import key as btckey

import functools as ft
import operator as op

from . import CrackException, log
from .keyconv import int_to_32or64bytes
from .teslafile import Header


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
            yield prod, i


def _guess_key(primes, key_ok_predicate):
    """Returns the 1st key satisfying the predicate, or None."""
    for key, combid in _gen_product_combinations(primes):
        if key_ok_predicate(key):
            if log.isEnabledFor(logging.DEBUG):
                log.debug('Winning factors: %s',
                        [f for (j, f) in enumerate(primes) if combid & 1<<j])
            return key


def _guess_all_keys(primes, key_ok_predicate):
    """Returns the 1st or all candidate keys satisfying the predicate, or None."""
    keys = set()
    for key, combid in _gen_product_combinations(primes):
        if key not in keys and key_ok_predicate(key):
            keys.add(key)
            if log.isEnabledFor(logging.DEBUG):
                log.debug('Winning factors: %s',
                        [f for (j, f) in enumerate(primes) if combid & 1<<j])
    if keys:
        return list(keys)


#: Start-bytes for common file-types,
#:     used to validate if decrypt was successful.
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


def _make_ecdh_pub_bkey(ecdh_sec_exponent):
    return bytes(ecdsa.SigningKey.from_secret_exponent(ecdh_sec_exponent,
                curve=ecdsa.SECP256k1).verifying_key.to_string())


def crack_aes_key_from_file(fpath, primes):
    with open(fpath, "rb") as f:
        header = Header.from_fd(f)
        data = f.read(16)
    primes = _validate_factors_product(primes, header.conv('aes_mul_key', 'num'), allow_cofactor=True)

    def did_AES_produced_known_file(aes_test_key):
        file_bytes = AES.new(int_to_32or64bytes(aes_test_key), AES.MODE_CBC, header.iv).decrypt(data)
        return _is_known_file(fpath, file_bytes)

    candidate_keys = _guess_all_keys(primes, key_ok_predicate=did_AES_produced_known_file)
    log.debug('Candidate AES-keys: %s', candidate_keys)

    file_pub = header.conv('aes_pub_key', 'bin')
    for test_priv in candidate_keys:
        gen_pub = _make_ecdh_pub_bkey(test_priv)
        if file_pub.startswith(gen_pub):
            return test_priv


def crack_btc_key_from_btc_address(btc_address, primes, btc_mul_key=None):
    primes = _validate_factors_product(primes, btc_mul_key, allow_cofactor=True)

    def does_key_gen_my_btc_address(btc_test_key):
        test_addr = btckey.Key(btc_test_key).address(use_uncompressed=True)
        return test_addr == btc_address

    return _guess_key(primes, key_ok_predicate=does_key_gen_my_btc_address)


def crack_ecdh_key(ecdsa_pub_key, mul_key, primes):
    primes = _validate_factors_product(primes, mul_key, allow_cofactor=True)

    def does_key_gen_my_ecdh(test_key):
        gen_pub = _make_ecdh_pub_bkey(test_key)
        return ecdsa_pub_key.startswith(gen_pub)

    return _guess_key(primes, key_ok_predicate=does_key_gen_my_ecdh)


def _decide_which_key(primes, aes_mul, btc_mul, file):
    primes = _validate_factors_product(primes)
    prod = product(primes)
    is_aes = prod % aes_mul == 0
    is_btc = prod % btc_mul == 0
    if not (is_aes ^ is_btc):
        raise CrackException("Factors divide both or none AES and BTC mul-keys!"
                "\n  Either too few factors or bad factors given."
                "\n  AES(divide=%s): %s\n  BTC(divide=%s): %s",
                is_aes, aes_mul, is_btc, btc_mul)
    if is_aes:
        key_name = 'AES'
        mul_key = aes_mul
    else:
        key_name = 'BTC'
        mul_key = btc_mul
    cofactor = mul_key // prod
    if cofactor != 1:
        primes.append(cofactor)
        log.warning("Incomplete factorization for %s mul-key on file(%s), found cofactor(%d)!",
                key_name, file, cofactor)
    else:
        log.info("Guessing %s-mul-key on file(%s): \n  %s",
                key_name, file, mul_key)
    return sorted(primes), key_name


def crack_ecdh_key_from_file(file, primes):
    with open(file, "rb") as f:
        header = Header.from_fd(f)
    aes_mul = int(header.conv('aes_mul_key', 'fix'), 16)
    aes_ecdh = header.aes_pub_key
    btc_mul = int(header.conv('btc_mul_key', 'fix'), 16)
    btc_ecdh = header.btc_pub_key
    primes, key_name = _decide_which_key(primes, aes_mul, btc_mul, file)

    def does_key_gen_my_ecdh(key):
        gen_ecdh = ecdsa.SigningKey.from_secret_exponent(
                key, curve=ecdsa.SECP256k1).verifying_key
        gen_ecdh = bytes(gen_ecdh.to_string())
        return aes_ecdh.startswith(gen_ecdh) or btc_ecdh.startswith(gen_ecdh)

    key = _guess_key(primes, key_ok_predicate=does_key_gen_my_ecdh)
    return (key_name, key) if key else (None, None)
