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
from __future__ import print_function
import sys

def main(file, *primes):
    import ecdsa

    pubkeys = {}
    known_file_magics = ['\xde\xad\xbe\xef\x04', '\x00\x00\x00\x00\x04']

    prod = 1
    for p in primes:
        if int(p) >= 1<<256:
            return "Factor too large: %s" % p
        prod *= int(p)

    with open(file, "rb") as f:
        header = f.read(414)
        if header[:5] not in known_file_magics:
            return file + " doesn't appear to be TeslaCrypted"
        ecdh = int(header[0x45:0xc5].rstrip('\0'), 16)
        cofactor = ecdh/prod
        if cofactor*prod != ecdh:
            ecdh = int(header[0x108:0x188].rstrip('\0'), 16)
            cofactor = ecdh/prod
        if prod > ecdh:
            return "Superfluous factors or incorrect factorization detected!"
        if cofactor*prod != ecdh:
            return "Error: factors don't divide either pubkey"

        i = 1
        while i < 1<<len(primes):
            x = 1
            for j in range(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if x < 1<<256 and ecdh/x < 1<<256:
                if x not in pubkeys:
                    pubkeys[x] = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1).verifying_key.to_string()
                if header[5:].startswith(pubkeys[x]):
                    return "Found Bitcoin private key: %064X" % x
                elif header[200:].startswith(pubkeys[x]):
                    return "Found AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in range(0, 64, 2)]) + "' (%064X)" % x
            i += 1

        i = 1
        while i < 1<<len(primes):
            x = cofactor
            for j in range(len(primes)):
                if i & 1<<j:
                    x *= int(primes[j])
            if x < 1<<256 and ecdh/x < 1<<256:
                if x not in pubkeys:
                    pubkeys[x] = ecdsa.SigningKey.from_secret_exponent(x, curve=ecdsa.SECP256k1).verifying_key.to_string()
                if header[5:].startswith(pubkeys[x]):
                    return "Found Bitcoin private key: %064X" % x
                elif header[200:].startswith(pubkeys[x]):
                    return "Found AES private key: b'\\x" + '\\x'.join([('%064x' % x)[i:i+2] for i in range(0, 64, 2)]) + "' (%064X)" % x
            i += 1

        if cofactor != 1:
            return "No keys found, incomplete factorization!"

    return "No keys found, check your factors!"

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: unfactor_ecdsa.py <sample file> <space-separated list of factors>")
        exit()
    print(main(sys.argv[1:]))
