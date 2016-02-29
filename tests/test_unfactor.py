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
from teslacrack import __main__ as tcm
from teslacrack import unfactor
import textwrap
import unittest

import ddt
import yaml


tcm.init_logging(level=logging.DEBUG)


app_db_txt = r"""
keys:
    - name     : ankostis
      type     : AES
      mul_key: 7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA
      decrypted: 017B1647D4242BC67CE8A6AAEC4D8B493F35519BD82775623D86182167148DD9
      factors  :
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
      crypted_files:
        - tesla2.pdf.vvv

    - name     : hermanndp
      type     : AES
      mul_key: 07E18921C536C112A14966D4EAAD01F10537F77984ADAAE398048F12685E2870CD1968FE3317319693DA16FFECF6A78EDBC325DDA2EE78A3F9DF8EEFD40299D9
      decrypted: 1b5c52aafcffda2e71001cf1880fe45cb93dea4c71328df595cb5eb882a3979f
      factors  :
        - 13
        - 3631
        - 129949621
        - 772913651
        - 7004965235626057660321517749245179
        - 4761326544374734107426225922123841005827557
        - 2610294590708970742101938252592668460113250757564649051
      crypted_files:
        - tesla_key3.doc.vvv
        - tesla_key3.pdf.zzz

    - name     : gh-14
      type     : BTC
      mul_key: 372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C
      decrypted: 38F47CB4BB4B0E2DA4AF771D618E9575520781F17E5785480F51B7955216D71F
      btc_addr : 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4
      factors  :
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
      crypted_files:
        - tesla_key14.jpg.vvv

    - name     : unknown1
      type     : AES
      mul_key: 5942f9a9aff
      factors  : [13, 3631, 129949621, 999999]
      error    : Extra factors given

    - name     : unknown2
      type     : AES
      mul_key: 5942f9a9aff
      factors  : [3631, 129949621]
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
        cls.longMessage = True ## Print also original assertion msg.
        os.chdir(osp.join(osp.dirname(__file__), 'teslafiles'))

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_from_file(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            exp_aes_key = key_rec.get('decrypted')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['factors']]
            aes_key = unfactor.crack_aes_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIsNotNone(aes_key, msg=key_rec)
            self.assertIn(exp_aes_key.upper(), '%064X' % aes_key, msg=key_rec)

#     @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
#     def test_unfactor_key_failures(self, key_rec):
#         factors = [int(fc) for fc in key_rec['factors']]
#         exp_aes_key = key_rec.get('decrypted')
#         if not exp_aes_key:
#             crypted_aes_key = int(key_rec['mul_key'], 16)
#             unfactor.crack_aes_key_from_file('<fpath>', factors, crypted_aes_key,
#                     lambda *args: b'')
#             err_msg = cm.exception.args[0]
#             self.assertIn(key_rec['error'], err_msg, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_ecdh_BTC_from_file(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            exp_aes_key = key_rec.get('decrypted')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['factors']]
            key_name, key = unfactor.crack_ecdh_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key.upper(), '0x%064X'%key, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'AES'])
    def test_unfactor_ecdh_AES_from_file(self, key_rec):
        for f in key_rec.get('crypted_files', ()):
            exp_aes_key = key_rec.get('decrypted')
            if not exp_aes_key:
                continue
            factors = [int(fc) for fc in key_rec['factors']]
            key_name, key = unfactor.crack_ecdh_key_from_file(f, factors)
            #print(key_rec['name'], f, aes_keys, exp_aes_key)
            self.assertIn(exp_aes_key.upper(), '0x%064X'%key, msg=key_rec)

    @ddt.data(*[k for k in app_db['keys'] if k['type'] == 'BTC'])
    def test_unfactor_btc_address(self, key_rec):
        dec_key = key_rec.get('decrypted')
        btc_addr = key_rec.get('btc_addr')
        if btc_addr:
            factors = [int(fc) for fc in key_rec['factors']]
            btc_key = unfactor.crack_btc_key_from_btc_address(btc_addr, factors)
            #print(key_rec['name'], btc_addr, dec_key)
            self.assertIsNotNone(btc_key, msg=key_rec)
            self.assertIn(dec_key.upper(), '0x%064X' % btc_key, msg=key_rec)
