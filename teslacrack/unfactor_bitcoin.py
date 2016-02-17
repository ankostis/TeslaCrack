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

from teslacrack import (CrackException, validate_factors_product,
                        gen_product_combinations)


try:
    from pybitcoin.keypair import BitcoinKeypair
except ImportError:
    from coinkit.keypair import BitcoinKeypair


def unfactor_btc_key(btc_address, primes, public_btc=None):
    primes = validate_factors_product(primes, public_btc, allow_cofactor=False)

    for key in gen_product_combinations(primes):
        test_addr = BitcoinKeypair(key).address()
        if test_addr == btc_address:
            return key
    raise CrackException("Failed reconstructing BTC-key! "
            "\n  Re-validate your your prime-factors.")
