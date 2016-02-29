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

import sys
from teslacrack import CrackException


def main(addr, *primes):
    try:
        from pybitcoin.keypair import BitcoinKeypair
    except ImportError:
        from coinkit.keypair import BitcoinKeypair

    primes = [int(p) for p in primes]
    addrs = {}
    prod = 1
    for p in primes:
        if p >= 1<<256:
            raise CrackException("Factor too large: %s" % p)
        prod *= p
    if prod >= 1<<512:
        raise CrackException("Superfluous factors or incorrect factorization detected!")

    i = 1
    while i < 1<<len(primes):
        x = 1
        for j, p in enumerate(primes):
            if i & 1<<j:
                x *= p
        if x < 1<<256 and prod/x < 1<<256:
            if x not in addrs:
                addrs[x] = BitcoinKeypair(x).address()
                if addr == addrs[x]:
                    return "Found Bitcoin private key: %064X" % x
        i += 1

    raise CrackException("No keys found, check your factors!")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor-bitcoin.py <bitcoin address> <space-separated list of factors>")
        exit()
    try:
        print(main(sys.argv[1], *sys.argv[2:]))
    except CrackException as ex:
        log.error("Reconstruction failed! %s", ex)
