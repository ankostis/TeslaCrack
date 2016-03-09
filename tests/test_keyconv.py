#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import print_function, unicode_literals, division

import logging
from teslacrack import __main__ as tcm, keyconv
from teslacrack.keyconv import AKey
import unittest

import ddt
from future.builtins import str, int, bytes  # @UnusedImport

from _tutils  import assertRegex, assertNotRegex
import itertools as itt


tcm.init_logging(level=logging.DEBUG)


_key = bytes(b"\x9b*\x14R\x9f\\\xefd\x9f\xd03\r\x15\xb4\xe5\x9a\x9f`HM\xb5\xd0D\xe4Ouu!\x85\x0b\xc8\xe1\xdc\xdf<\xb7p\xfe\xe0\xdd+jwB\xb9\x93\x00\xed\x02\x100'\xb7B\xbc\x86!\x10\xa1vZ\x8bO\xc6")
_key_variations = [
    b"\x9b*\x14R\x9f\\\xefd\x9f\xd03\r\x15\xb4\xe5\x9a\x9f`HM\xb5\xd0D\xe4Ouu!\x85\x0b\xc8\xe1\xdc\xdf<\xb7p\xfe\xe0\xdd+jwB\xb9\x93\x00\xed\x02\x100'\xb7B\xbc\x86!\x10\xa1vZ\x8bO\xc6",
    8126617599207443348986490006049212956268718489283948438673983714596683304044955742664060883447819181330966710002780429642374333138816650318920123595575238,
    '0x9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6',
    '9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6',
    'myoUUp9c72Sf0DMNFbTlmp9gSE210ETkT3V1IYULyOHc3zy3cP7g3Stqd0K5kwDtAhAwJ7dCvIYhEKF2WotPxg==',
]

def _gen_non_byte_keys():
    for k in _key_variations:
        yield k
        if not isinstance(k, int):
            for frmt in ('%s',
                    'u"%s"', b'u"%s"',
                    "u'%s'", b"u'%s'"
                    ):
                try:
                    #print(frmt, k)
                    yield frmt % k
                except (TypeError, UnicodeError):
                    pass

def _gen_byte_keys():
    for k in _key_variations[1:]:
        if not isinstance(k, int):
            for frmt in ('b"%s"', b'b"%s"',
                        "b'%s'", b"b'%s'"):
                try:
                    #print(frmt, k)
                    yield frmt % k
                except (TypeError, UnicodeError):
                    pass


@ddt.ddt
class TAutonvertKey(unittest.TestCase):

    @ddt.data(*itt.product(
            ["b'%s'", 'b"%s"', "u'%s'", 'u"%s"', '"%s"', "'%s'"],
                          ['', 'ABCDE123', 'ABCDE\'123', 'ABCDE"123',
                              "'ABCDE123'", '"ABCDE123"',
                              '"ABCDE\'123"', '\'ABCDE\'123\'',
                              '"ABCDE"123"', "'ABCDE\"123'"]))
    def test_unquote_b_str_regex(self, case):
        quotes, unquoted = case
        quoted = quotes % unquoted
        m = keyconv._unquote_b_str_regex.match(quoted)  # @UndefinedVariable
        self.assertIsNotNone(m, quoted)
        self.assertEqual(m.group(2), unquoted)

    @ddt.data(*itt.product(
            ["u'%s'", 'u"%s"', '"%s"', "'%s'"],
                          ['', 'ABCDE123', 'ABCDE\'123', 'ABCDE"123',
                              "'ABCDE123'", '"ABCDE123"',
                              '"ABCDE\'123"', '\'ABCDE\'123\'',
                              '"ABCDE"123"', "'ABCDE\"123'"]))
    def test_unquote_str_regex(self, case):
        quotes, unquoted = case
        quoted = quotes % unquoted
        m = keyconv._unquote_b_str_regex.match(quoted)  # @UndefinedVariable
        self.assertIsNotNone(m, quoted)
        self.assertEqual(m.group(2), unquoted)

    @ddt.data(*itt.product(["b%s'", 'b%s"', "u%s'", 'u%s"',
                            "b'%s", 'b"%s', "u'%s", 'u"%s',
                            'u%s', 'b%s', '%s', '%s"', '"%s', "'%s", "%s'"],
                          ['ABCDE123', 'ABCDE\'123', 'ABCDE"123', '']))
    def test_unquote_str_regex2(self, case):
        quoted, unquoted = case
        quoted %= unquoted
        self.assertEqual(keyconv._unquote(quoted), quoted)

    @ddt.data(*list(_gen_non_byte_keys()))
    def test_autoconv_non_bytes(self, key):
        autokey = keyconv._autoconv_to_bytes(key)[1]
        self.assertEqual(autokey, _key)

    @ddt.data(*list(_gen_byte_keys()))
    def test_autoconv_bytes(self, key):
        autokey = keyconv._autoconv_to_bytes(key)[1]
        self.assertNotEqual(autokey, _key)

    def test_autoconv_to_bytes2(self):
        key='07e18921c536c112a14966d4eaad01f10537f77984adaae398048f12685e2870cd1968fe3317319693da16ffecf6a78edbc325dda2ee78a3f9df8eefd40299d9'
        exp_bytes= b'\x07\xe1\x89!\xc56\xc1\x12\xa1If\xd4\xea\xad\x01\xf1\x057\xf7y\x84\xad\xaa\xe3\x98\x04\x8f\x12h^(p\xcd\x19h\xfe3\x171\x96\x93\xda\x16\xff\xec\xf6\xa7\x8e\xdb\xc3%\xdd\xa2\xeex\xa3\xf9\xdf\x8e\xef\xd4\x02\x99\xd9'
        autokey = keyconv._autoconv_to_bytes(key)[1]
        self.assertEqual(autokey, exp_bytes)

    def test_autoconv_to_bytes_plainbytes(self):
        key = b'\xae~\x9a\xf9)\x84\xa7\x955\x15$\xc3$>\xb6A\xcd\x03\x13F\xa7\xa9\xd4tK+\x1b"\xfdn\xf4\xe1S\xfa\x81\x17\x04\x8c\x11R+\xa4\xa0\xb9\t\xc3k=AF\xcbo\x13x\x82\xdf\xa2\xb2\xdeo&\xf0Y\x8d'
        exp_bytes = key
        autokey = keyconv._autoconv_to_bytes(key)[1]
        self.assertEqual(autokey, exp_bytes)

    def test_autoconv_smallbytes(self):
        key = "b'1234'"
        exp_bytes = b'1234'
        autokey = keyconv._autoconv_to_bytes(key)[1]
        self.assertEqual(autokey, exp_bytes)


@ddt.ddt
class TAKey(unittest.TestCase):

    @ddt.data(b'', b'\0', b'\x00123456')
    def test_byte_equality(self, b):
        ak = AKey(b)
        self.assertEqual(ak, b, b)
        self.assertEqual(bytes(b), ak, b)
        self.assertEqual(ak, bytes(b), b)

        bb = AKey(bytes(b))
        self.assertEqual(b, bb, b)
        self.assertEqual(bb, b, b)
        self.assertEqual(bytes(b), bb, b)
        self.assertEqual(bb, bytes(b), b)

        bbb = bytes(ak)
        self.assertEqual(     bbb, ak, b)
        self.assertEqual(bb, b, b)
        self.assertEqual(bytes(b), bb, b)
        self.assertEqual(bb, bytes(b), b)

    @ddt.data(b'', b'\0', b'\x00123456')
    def test_byte_hash_equality(self, b):
        ak = AKey(b)
        self.assertEqual(hash(ak), hash(b), b)

    @ddt.data(b'', b'\x00a', b'\x00abc')
    def test_types(self, b):
        ak = AKey(b)
        self.assertEqual(type(bytes(ak)), type(bytes(b)), b)
        self.assertIsInstance(ak, type(b''), b)
        self.assertIsInstance(ak, bytes, b)

    @ddt.data(b'', b'\x00a', b'\x00abc')
    def test_byte_startwith(self, b):
        bb = b'\x00abc'
        ak = AKey(b)
        ak2 = AKey(bb)
        self.assertTrue(ak2.startswith(b), b)
        self.assertTrue(ak2.startswith(ak), b)
        #self.assertTrue(bb.startswith(AKey(b)), b) # XXX: bytes's problem!

    @ddt.data(b'', b'\x00a', b'\x00\fc\n\r\x00\x19')
    def test_byte_repr(self, b):
        v = repr(AKey(b, 'bin'))
        assertRegex(self, v, 'b(\'.*\')|(b".*")', b)

    @ddt.data(*itt.product(['hex', 'asc', 'num'],
            [b'\x00a', b'\x00\fc\n\r\x00\x19']))
    def test_byte_repr_non_bytes(self, case):
        conv, b = case
        v = repr(AKey(b, conv))
        assertNotRegex(self, v, 'b(\'.*\')|(b".*")', b)

    @ddt.data(0, 10, 16, 1<<64, 1<<128)
    def test_hex_conv_equals_hex_number(self, n):
        ak = AKey.auto(n)
        self.assertEqual(ak.num, int(ak.hex, 16))

    def test_indexing(self):
        d = {b'\x00abc': 1, b'\x00ab': 2, b'\x00df': 3}
        pk = dict((AKey(k), v) for k,v in d.items())
        self.assertEqual(pk[b'\x00df'], 3)
        self.assertEqual(pk[bytes(b'\x00df')], 3)
        self.assertEqual(pk[AKey(b'\x00df')], 3)

    def test_key_suffix(self):
        k= b'7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA'
        ak1 = AKey.auto(k)
        self.assertTrue(ak1.bin[-1] != 0, ak1.bin[-3:])
        k= '7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA'
        ak2 = AKey.auto(k)
        self.assertTrue(ak2.bin[-1] != 0, ak2.bin[-3:])
        self.assertEqual(ak1, ak2)
