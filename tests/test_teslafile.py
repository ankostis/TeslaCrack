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
#
## TestCases for teslacrack.
##
## It needs a `bash` (cygwin or git-for-windows) because that was an easy way
## to make files/dirs inaccessible, needed for TCs.
from __future__ import print_function, unicode_literals, division

from os import path as osp
import os
from teslacrack import __main__ as tcm
from teslacrack import teslafile, CrackException
import unittest

import ddt
from future.builtins import str, int, bytes  # @UnusedImport
from future.utils import PY2

import itertools as itt


from _tutils import assertRaisesRegex, assertRegex  # @NoMove


tcm.init_logging()

def _tf_fpath(fname):
    return osp.join(osp.dirname(__file__), 'teslafiles', fname)


class TTeslafile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg.


    def test_reading_invalid_tesla_file_smaller(self):
        f = 'tesla_smaller_size.jpg.vvv'
        with open(_tf_fpath(f), 'rb') as fd:
            with assertRaisesRegex(self, CrackException,
                    ' magic-bytes.+ OK\\? True, file-size.+ OK\\? False'):
                teslafile.Header.from_fd(fd)

    def test_reading_invalid_tesla_file_bad_magic(self):
        f = 'tesla_invalid_magic.pdf.ccc'
        with open(_tf_fpath(f), 'rb') as fd:
            with assertRaisesRegex(self, CrackException,
                    ' magic-bytes.+ OK\\? False, file-size.+ OK\\? True'):
                teslafile.Header.from_fd(fd)

    def test_reading_invalid_tesla_file_ugly_mul_AES_key(self):
        f = 'tesla_ugly_aeskey.pdf.ccc'
        with open(_tf_fpath(f), 'rb') as fd:
            with assertRaisesRegex(self, CrackException,
                    'keys might be corrupted: '):
                teslafile.Header.from_fd(fd)

mydir = os.path.dirname(__file__)

_sample_header = teslafile.Header( # From file: tesla_key14.jpg.vvv
    start=b'\0\0\0\0\x04',
    btc_pub_key=b'\x17z^\ts\xea4\xff\xae\xba\x8b\xab\xa6\xf8\x8fN\xd1M9CU\x9d{\x16=\xda\xc8\xd4\xdf\xe9\xe5\xa8\x92\xd9(m\xbd\xb5o]\x8e\xd1f\x85\xd5VOb\xfa\xfdD\x1f~\xb4\x0e\xc6*\xf7>\x07s\xd7n\xb1',
    btc_mul_key=b'372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C\x00\x00',
    aes_pub_key=b'\x04C\xc3\xfe\x02F\x05}\x066\xd0\xca\xbb}\x8e\xe9\x847\xe6\xe6\xc0\xfe2J#\xee\x1aO\xd8\xc5\x1d\xbc\x06\xd9.m\xe51@\xb0W\xc5\x18P\xe1\rr\xc5\xa2\xce\t\x81\x80u\xd4\x12\xf1\xda\xb7r\x9e\xe4\xd6&\xfe',
    aes_mul_key=b'9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6\x00\x00',
    iv=b"'Q\n\xbf1\x8di&\x17x\x97+\x98}\xf6\x9f",
    size=7188492
)
_sample_size = _sample_header.size
_key_fields = ('btc_pub_key', 'aes_pub_key') + teslafile._hex_fields


def _all_prefixes(s):
    return (s[:i] for i in range(1, len(s)))

_all_hconv_names = teslafile.Header._trans_maps.keys()
_all_fields = teslafile.Header._fields  # @UndefinedVariable

@ddt.ddt
class THeader(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.


    @ddt.data(*itt.product(['raw', 'fix', 'bin'], _all_fields))  # @UndefinedVariable
    def test_hconv_bytes(self, case):
        hconv, fld = case
        h = teslafile.Header(*_sample_header)
        if not (fld == 'size' and hconv == 'fix'):
            assertRegex(self, repr(h.conv(fld, hconv)), '^b(\'.*\')|(b".*")$', fld)

    @ddt.data(*itt.product(['xhex', 'hex', 'num', '64'], _all_fields))  # @UndefinedVariable
    def test_hconv_non_bytes(self, case):
        hconv, fld = case
        h = teslafile.Header(*_sample_header)
        v = h.conv(fld, hconv)
        if not (fld == 'size' and hconv in 'num', '64'):
            self.assertNotRegex(v, '^b(\'.*\')|(b".*")$', fld)

    @ddt.data(*(f for f in _all_fields if f != 'size'))  # @UndefinedVariable
    def test_hconv_hex_numbers_equal(self, fld):
        h = teslafile.Header(*_sample_header)
        ahex = int(str(h.conv(fld, 'hex')), 16)
        xhex = int(str(h.conv(fld, 'xhex')), 16)
        self.assertEqual(ahex, xhex)

    @ddt.data(*_all_fields)
    def test_hconv_xhex_digits(self, fld):
        h = teslafile.Header(*_sample_header)
        assertRegex(self, h.conv(fld, 'xhex'), '(?i)^[0-9a-f]*$', fld)

    @ddt.data(*_all_fields)
    def test_hconv_hex_digits(self, fld):
        h = teslafile.Header(*_sample_header)
        assertRegex(self, h.conv(fld, 'hex'), '(?i)^0x[0-9a-f]*$', fld)

    @ddt.data(*_all_hconv_names)
    def test_hconv_int_size(self, hconv):
        h = teslafile.Header(*_sample_header)
        sz = h.conv('size', hconv)
        if hconv in ('fix', 'num', '64'):
            self.assertEqual(sz, _sample_size, hconv)
        else:
            self.assertNotEqual(sz, _sample_size, hconv)

    def test_hconv_hex_size(self):
        h = teslafile.Header(*_sample_header)
        self.assertEqual(int(h.conv('size', 'hex'), 16), _sample_size)

    @ddt.data(*_key_fields)
    def test_hconv_b64_length_threshold(self, fld):
        h = teslafile.Header(*_sample_header)
        v = h.conv(fld, '64')
        self.assertGreater(len(v), 30)
        self.assertIsInstance(v, str)

    @ddt.data(*_key_fields)
    def test_hconv_compare_lengths(self, fld):
        h = teslafile.Header(*_sample_header)
        self.assertEqual(len(h.conv(fld, 'xhex')) + 2,   len(h.conv(fld, 'hex')), fld)
        self.assertEqual(len(h.conv(fld, 'xhex')),       len(h.conv(fld, 'bin')) * 2, fld)
        self.assertGreaterEqual(len(h.conv(fld, 'raw')), len(h.conv(fld, 'fix')), fld)
        self.assertGreater(len(h.conv(fld, 'xhex')),     len(h.conv(fld, '64')), fld)

    @unittest.skipIf(PY2, 'String-comparison fail in PY2')
    def test_str(self):
        h = teslafile.Header(*_sample_header)
        s = str(h)
        #print(s)
        exp_str = """
                start: '0x0000000004'
          btc_pub_key: '0x177a5e0973ea34ffaeba8baba6f88f4ed14d3943559d7b163ddac8d4dfe9e5a892d9286dbdb56f5d8ed16685d5564f62fafd441f7eb40ec62af73e0773d76eb1'
          btc_mul_key: '0x372ae820bbf2c3475e18f165f46772087effc7d378a3a4d10789ae7633ec09c74578993a2a7104eba577d229f935af77c647f18e113647c25ef19cc7e4ee3c4c'
          aes_pub_key: '0x0443c3fe0246057d0636d0cabb7d8ee98437e6e6c0fe324a23ee1a4fd8c51dbc06d92e6de53140b057c51850e10d72c5a2ce09818075d412f1dab7729ee4d626fe'
          aes_mul_key: '0x9b2a14529f5cef649fd0330d15b4e59a9f60484db5d044e44f757521850bc8e1dcdf3cb770fee0dd2b6a7742b99300ed02103027b742bc862110a1765a8b4fc6'
                   iv: '0x27510abf318d69261778972b987df69f'
                 size: '0x6db00c'"""
        self.assertSequenceEqual(s.split(), exp_str.split())


_bin_fields = (f for f in _all_fields if f != 'size')

@ddt.ddt
class TFileSubcmd(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.

    @ddt.data(*[(conv, pref) for conv in _all_hconv_names for pref in _all_prefixes(conv)])
    def test_hconv_prefixmatch(self, case):
        exp_conv, prefix = case
        conv = teslafile.match_header_conv(prefix)
        self.assertEqual(conv, exp_conv)

    @ddt.data(*_bin_fields)
    def test_singe_fields_raw(self, fld):
        file = _tf_fpath('tesla_key14.jpg.vvv')
        opts = {'<file>': file, '<field>': [fld], '-F': 'r'}
        res = tcm._show_file_headers(opts)
        self.assertIn(res, getattr(_sample_header, fld))

    def test_all_fields_is_multiline(self):
        file = _tf_fpath('tesla_key14.jpg.vvv')
        opts = {'<file>': file, '<field>': [], '-F': 'r'}
        res = tcm._show_file_headers(opts)
        self.assertEqual(len(res.split('\n')), len(_all_fields))

    def test_bad_fields_screams(self):
        file = _tf_fpath('tesla_key14.jpg.vvv')
        opts = {'<file>': file, '<field>': ['BAD_GOO!'], '-F': 'r'}
        with assertRaisesRegex(self, CrackException, 'Must be a case-insensitive subs-string of:'):
            tcm._show_file_headers(opts)

