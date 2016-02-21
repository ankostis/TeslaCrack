#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import unicode_literals

import os
import struct
from teslacrack import teslafile, key as tckey
import unittest

import ddt
from future.builtins import str

import itertools as itt
import teslacrack as tc


try:
    assertRegex = unittest.TestCase.assertRegex
    assertNotRegex = unittest.TestCase.assertNotRegex
except AttributeError:
    ## Checks also hconv-names uniquely prefixed.
    assertRegex = unittest.TestCase.assertRegexpMatches
    assertNotRegex = unittest.TestCase.assertNotRegexpMatches  # @UndefinedVariable

mydir = os.path.dirname(__file__)

_sample_header = teslafile.Header(
    start=b'\0\0\0\0',
    pub_btc=b'\x04\x17z^\ts\xea4\xff\xae\xba\x8b\xab\xa6\xf8\x8fN\xd1M9CU\x9d{\x16=\xda\xc8\xd4\xdf\xe9\xe5\xa8\x92\xd9(m\xbd\xb5o]\x8e\xd1f\x85\xd5VOb\xfa\xfdD\x1f~\xb4\x0e\xc6*\xf7>\x07s\xd7n\xb1',
    priv_btc=b'372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C\x00\x00',
    pub_aes=b'\x04C\xc3\xfe\x02F\x05}\x066\xd0\xca\xbb}\x8e\xe9\x847\xe6\xe6\xc0\xfe2J#\xee\x1aO\xd8\xc5\x1d\xbc\x06\xd9.m\xe51@\xb0W\xc5\x18P\xe1\rr\xc5\xa2\xce\t\x81\x80u\xd4\x12\xf1\xda\xb7r\x9e\xe4\xd6&\xfe',
    priv_aes=b'9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6\x00\x00',
    iv=b"'Q\n\xbf1\x8di&\x17x\x97+\x98}\xf6\x9f",
    size=b'\x0c\xb0m\x00'
)
_sample_size = struct.unpack('<I', _sample_header.size)[0]

def _all_prefixes(s):
    return (s[:i] for i in range(1, len(s)))

_all_iconv_names = list(itt.chain(*[_all_prefixes(k) for k in tckey._htrans_map.keys()]))

@ddt.ddt
class TTeslacrack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.


    @ddt.data(*_all_iconv_names)
    def test_hconv_prefixmatch_smoketest(self, hconv):
        h = tckey._convert_header(_sample_header, hconv)

    @ddt.data(*itt.product(['raw', 'fix', 'bin'], teslafile.Header._fields))
    def test_hconv_bytes(self, case):
        hconv, fld = case
        h = tckey._convert_header(_sample_header, hconv)
        if not (fld == 'size' and hconv == 'fix'):
            assertRegex(self, getattr(h, fld), '^b(\'.*\')|(b".*")$', fld)

    @ddt.data(*itt.product(['xhex', 'hex', 'num', '64'], teslafile.Header._fields))
    def test_hconv_non_bytes(self, case):
        hconv, fld = case
        h = tckey._convert_header(_sample_header, hconv)
        v = getattr(h, fld)
        if not (fld == 'size' and hconv in 'num', '64'):
            self.assertNotRegex(v, '^b(\'.*\')|(b".*")$', fld)

    @ddt.data(*itt.product(['hex', 'xhex'], teslafile.Header._fields))
    def test_hconv_hex_numbers_smoketest(self, case):
        hconv, fld = case
        h = tckey._convert_header(_sample_header, hconv)
        int(str(getattr(h, fld)), 16)

    @ddt.data(*teslafile.Header._fields)
    def test_hconv_xhex_digits(self, fld):
        h = tckey._convert_header(_sample_header, 'xhex')
        assertRegex(self, getattr(h, fld), '(?i)^[0-9a-f]*$', fld)

    @ddt.data(*teslafile.Header._fields)
    def test_hconv_hex_digits(self, fld):
        h = tckey._convert_header(_sample_header, 'hex')
        assertRegex(self, getattr(h, fld), '(?i)^0x[0-9a-f]*$', fld)

    @ddt.data('fix', 'num', '64')
    def test_hconv_int_size(self, hconv):
        h = tckey._convert_header(_sample_header, hconv)
        self.assertEqual(h.size, _sample_size, hconv)

    def test_hconv_hex_size(self):
        h = tckey._convert_header(_sample_header, 'hex')
        self.assertEqual(int(h.size, 16), _sample_size)


@ddt.ddt
class TAutonvertKey(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.

    @ddt.data(*itt.product(
            ["b'%s'", 'b"%s"', "u'%s'", 'u"%s"', '"%s"', "'%s'"],
                          ['', 'ABCDE123', 'ABCDE\'123', 'ABCDE"123',
                              "'ABCDE123'", '"ABCDE123"',
                              '"ABCDE\'123"', '\'ABCDE\'123\'',
                              '"ABCDE"123"', "'ABCDE\"123'"]))
    def test_unquote_str_regex(self, case):
        quoted, unquoted = case
        quoted %= unquoted
        m = tckey._unquote_str_regex.match(quoted)
        self.assertIsNotNone(m, quoted)
        self.assertEqual(m.group(2), unquoted)

    @ddt.data(*itt.product(["b%s'", 'b%s"', "u%s'", 'u%s"',
                            "b'%s", 'b"%s', "u'%s", 'u"%s',
                            'u%s', 'b%s', '%s', '%s"', '"%s', "'%s", "%s'"],
                          ['ABCDE123', 'ABCDE\'123', 'ABCDE"123', '']))
    def test_unquote_str_regex2(self, case):
        quoted, unquoted = case
        quoted %= unquoted
        m = tckey._unquote_str_regex.match(quoted)
        self.assertIsNone(m, quoted)
