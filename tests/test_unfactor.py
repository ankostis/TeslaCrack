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
"""
TestCases for teslacrack.

It needs a `bash` (cygwin or git-for-windows) because that was an easy way
to make files/dirs inaccessible, needed for TCs.
"""
from __future__ import print_function, unicode_literals, division

import logging
from os import path as osp
import os
from teslacrack import __main__ as tcm, unfactor, keyconv
import textwrap
import unittest

import ddt
import yaml

import _tutils  # @UnusedImport


tcm.init_logging(level=logging.DEBUG)


app_db_txt = r"""
keys:
    - name:     ankostis
      type:     AES
      mul:     7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA
      prv:     017B1647D4242BC67CE8A6AAEC4D8B493F35519BD82775623D86182167148DD9
      primes:
        - 2
        - 7
        - 97
        - 131
        - 14983
        - 28099
        - 4030421
        - 123985129
        - 2124553904704757231
        - 2195185826800714519
        - 5573636538860090464486823831839
        - 23677274243760534899430414029178304942110152493113248247
      files:
        - tesla2.pdf.vvv

    - name:     hermanndp
      type:     AES
      mul:     07E18921C536C112A14966D4EAAD01F10537F77984ADAAE398048F12685E2870CD1968FE3317319693DA16FFECF6A78EDBC325DDA2EE78A3F9DF8EEFD40299D9
      prv:     1b5c52aafcffda2e71001cf1880fe45cb93dea4c71328df595cb5eb882a3979f
      primes:
        - 13
        - 3631
        - 129949621
        - 772913651
        - 7004965235626057660321517749245179
        - 4761326544374734107426225922123841005827557
        - 2610294590708970742101938252592668460113250757564649051
      files:
        - tesla_key3.doc.vvv
        - tesla_key3.pdf.zzz

    - name     : gh-14
      type     : BTC
      mul: 372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C
      prv: 38F47CB4BB4B0E2DA4AF771D618E9575520781F17E5785480F51B7955216D71F
      btc_addr : 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4
      primes:
        - 2
        - 2
        - 3
        - 7
        - 11
        - 17
        - 19
        - 139
        - 2311
        #- 1141326637
        - 14278309
        - 465056119273
        - 250220277466967
        - 373463829010805159059
        - 1261349708817837740609
        - 38505609642285116603442307097561327764453851349351841755789120180499
      files:
        - tesla_key14.jpg.vvv

    - name     : unknown1
      type     : AES
      mul: 5942f9a9aff
      primes: [13, 3631, 129949621, 999999]
      error    : Extra factors given

    - name     : unknown2
      type     : AES
      mul: 5942f9a9aff
      primes: [3631, 129949621]
      error    : Failed reconstructing AES-key!
      warning  : Incomplete factorization  ## UNUSED
"""

def read_app_db():
    return yaml.load(textwrap.dedent(app_db_txt))

app_db = read_app_db()


@ddt.ddt
class TUnfactor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(osp.join(osp.dirname(__file__), 'teslafiles'))

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_from_file(self, key_rec):
        for f in key_rec.get('files', ()):
            exp_aes_key = key_rec.get('prv')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['primes']]
            aes_key = unfactor.crack_aes_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIsNotNone(aes_key, msg=key_rec)
            self.assertIn(exp_aes_key.upper(), '%064X' % aes_key.num, msg=key_rec) ##TOD: Fix key comparisons and prints!

#     @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
#     def test_unfactor_key_failures(self, key_rec):
#         factors = [int(fc) for fc in key_rec['primes']]
#         exp_aes_key = key_rec.get('prv')
#         if not exp_aes_key:
#             crypted_aes_key = int(key_rec['mul'], 16)
#             unfactor.crack_aes_key_from_file('<fpath>', factors, crypted_aes_key,
#                     lambda *args: b'')
#             err_msg = cm.exception.args[0]
#             self.assertIn(key_rec['error'], err_msg, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_ecdh_BTC_from_file(self, key_rec):
        for f in key_rec.get('files', ()):
            exp_aes_key = key_rec.get('prv')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['primes']]
            _, key = unfactor.crack_ecdh_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key.upper(), '0x%064X'%key.num, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_ecdh_AES_from_file(self, key_rec):
        for f in key_rec.get('files', ()):
            exp_aes_key = key_rec.get('prv')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['primes']]
            _, key = unfactor.crack_ecdh_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key.upper(), '0x%064X'%key.num, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_btc_address(self, key_rec):
        dec_key = key_rec.get('prv')
        btc_addr = key_rec.get('btc_addr')
        if btc_addr:
            factors = [int(fc) for fc in key_rec['primes']]
            btc_key = unfactor.crack_btc_key_from_btc_address(btc_addr, factors)
            #print(key_rec['name'], btc_addr, dec_key)
            self.assertIsNotNone(btc_key, msg=key_rec)
            self.assertIn(dec_key.upper(), '0x%064X' % btc_key.num, msg=key_rec)

    def test_aes_from_btc(self):
        aes_pub = keyconv.AKey.auto(b'\xae~\x9a\xf9)\x84\xa7\x955\x15$\xc3$>\xb6A\xcd\x03\x13F\xa7\xa9\xd4tK+\x1b"\xfdn\xf4\xe1S\xfa\x81\x17\x04\x8c\x11R+\xa4\xa0\xb9\t\xc3k=AF\xcbo\x13x\x82\xdf\xa2\xb2\xdeo&\xf0Y\x8d')
        aes_mul = keyconv.AKey.auto('025B96A3F9AB13753ED84694034422216C03FD0298E67D87E9B1ACE8027D6C50F02CFD14724768AEA2BE2D53707661B554A8D5EAFA0D5CF3C3F2F299E614870F')
        btc_priv = keyconv.AKey.auto(b'\x9f\x0el`\x8a\xffw\x7f\x121\xd1\xd6\x91\xfb\x0f\xfe\x8b\xf2\x0c\xec\x13\xec\xbb\xcb\xa4\x99.Q4\x84b\xf2')

        exp_aes_priv = 55129851113444675798855803280729153325965425345465653744428349716537975545325
        gen_aes_priv = unfactor.aes_priv_from_btc_priv(aes_pub, btc_priv, aes_mul)
        self.assertEqual(gen_aes_priv.num, exp_aes_priv)

