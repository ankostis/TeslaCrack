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

import ecdsa

from . import (CrackException, gen_product_combinations,
               validate_factors_product, check_tesla_file, product)


def unfactor_key_from_file(file, primes):

    primes = validate_factors_product(primes)
    with open(file, "rb") as f:
        header = f.read(414)
    check_tesla_file(file, header[:5])
    prod = product(primes)
    ecdh = int(header[0x45:0xc5].rstrip('\0'), 16)
    key_name = 'BTC'
    cofactor = ecdh/prod
    if cofactor*prod != ecdh:
        key_name = 'AES'
        ecdh = int(header[0x108:0x188].rstrip('\0'), 16)
        cofactor = ecdh/prod
    if prod > ecdh:
        raise CrackException("Extra factors given, or factorization was incorrect!")
    if cofactor*prod != ecdh:
        raise CrackException("Factors don't divide neither AES nor BTC pubkeys!")
    if cofactor != 1:
        raise CrackException("Incomplete factorization!")


    for key in gen_product_combinations(primes):
        pub_key = ecdsa.SigningKey.from_secret_exponent(key,
                curve=ecdsa.SECP256k1).verifying_key.to_string()
        if header[5:].startswith(pub_key) or header[200:].startswith(pub_key):
            return key_name, key
    raise CrackException("Failed reconstructing %s-key! "
            "\n  Re-validate your your prime-factors." % key_name)
