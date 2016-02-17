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
"""
Bitcoin address-based TeslaCrypt key reconstructor

This is an alternative to unfactor-ecdsa.py, which should also work with
ancient versions of TeslaCrypt.

To use this tool, you need the Bitcoin address where ransom was expected to be paid,
as well as the 512-bit Bitcoin shared secret. This is typically found in the recovery
file, which is a text file named "RECOVERY_KEY.TXT", "recover_file.txt", or similar
dropped in the Documents folder by TeslaCrypt.
The first line of the recovery file is the Bitcoin address, while the 3rd line is
the shared secret. These values can also be obtained from key.dat, storage.bin
TeslaCrypt's registry entry, or (in case of TeslaCrypt 2.x) from the encrypted files
or from network packet dumps, in case the recovery file is lost.

Once you have these values, factor the shared secrets, then run this script with the
factors, like this:
unfactor-bitcoin.py <1st line of recovery file> <factors of 3rd line of recovery file>
The generated key can then be used with TeslaDecoder.
"""

from __future__ import print_function

import logging
import sys

import functools as ft
import operator as op
from teslacrack import CrackException


def product(factors):
    return ft.reduce(op.mul, factors)

log = logging.getLogger('unfactor_btc')


def main(addr, *primes):
    try:
        from pybitcoin.keypair import BitcoinKeypair
    except ImportError:
        from coinkit.keypair import BitcoinKeypair

    primes = [int(p) for p in primes]
    for p in primes:
        if p >= 1<<256:
            raise CrackException("Factor too large: %s" % p)
    primes_prod = product(primes)
    if primes_prod >= 1<<512:
        raise CrackException("Superfluous factors or incorrect factorization detected!")

    addrs = {}
    for i in range((1<<len(primes))-1, 1, -1):
        prod = product(p for j, p in enumerate(primes) if i & 1<<j)
        if prod < 1<<256 and primes_prod/prod < 1<<256 and prod not in addrs:
            addrs[prod] = gen_addr = BitcoinKeypair(prod).address()
            #print(bin(i), prod, gen_addr)
            if addr == gen_addr:
                return "Found Bitcoin private key: %064X" % prod

    raise CrackException("No keys found, check your factors!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        exit("usage: unfactor-bitcoin.py <bitcoin address> <space-separated list of factors>")
    try:
        print(main(sys.argv[1], *sys.argv[2:]))
    except CrackException as ex:
        log.error("Reconstruction failed! %s", ex)
