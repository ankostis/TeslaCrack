#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import unicode_literals

import logging
import unittest

import ddt
from future.builtins import str, int, bytes  # @UnusedImport

import itertools as itt
from teslacrack import __main__ as tcm, key as tckey


tcm.init_logging(level=logging.DEBUG)


_key = bytes(b"\x9b*\x14R\x9f\\\xefd\x9f\xd03\r\x15\xb4\xe5\x9a\x9f`HM\xb5\xd0D\xe4Ouu!\x85\x0b\xc8\xe1\xdc\xdf<\xb7p\xfe\xe0\xdd+jwB\xb9\x93\x00\xed\x02\x100'\xb7B\xbc\x86!\x10\xa1vZ\x8bO\xc6")
_key_variations = [
    b"\x9b*\x14R\x9f\\\xefd\x9f\xd03\r\x15\xb4\xe5\x9a\x9f`HM\xb5\xd0D\xe4Ouu!\x85\x0b\xc8\xe1\xdc\xdf<\xb7p\xfe\xe0\xdd+jwB\xb9\x93\x00\xed\x02\x100'\xb7B\xbc\x86!\x10\xa1vZ\x8bO\xc6",
    '9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6',
    '0x9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6',
    8126617599207443348986490006049212956268718489283948438673983714596683304044955742664060883447819181330966710002780429642374333138816650318920123595575238,
    'myoUUp9c72Sf0DMNFbTlmp9gSE210ETkT3V1IYULyOHc3zy3cP7g3Stqd0K5kwDtAhAwJ7dCvIYhEKF2WotPxg==',
]

def _gen_key_variations():
    for k in _key_variations:
        if isinstance(k, int):
            yield k
        else:
            yield k
#             yield (k ,'%s'%k,
#                 'b"%s"' % k , b'b"%s"' % k,
#                 'u"%s"' % k , b'u"%s"' % k,
#                 "b'%s'" % k , b"b'%s'" % k,
#                 "u'%s'" % k , b"u'%s'" % k,
#                 )

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
        self.assertEqual(tckey._unquote(quoted), quoted)

    @ddt.data(*list(_gen_key_variations()))
    def test_autoconv_to_bytes(self, key):
        autokey = tckey.autoconv_to_bytes(key)
        self.assertEqual(autokey, _key)

    def test_autoconv_to_bytes2(self):
        key='07e18921c536c112a14966d4eaad01f10537f77984adaae398048f12685e2870cd1968fe3317319693da16ffecf6a78edbc325dda2ee78a3f9df8eefd40299d9'
        exp_bytes= b'\x07\xe1\x89!\xc56\xc1\x12\xa1If\xd4\xea\xad\x01\xf1\x057\xf7y\x84\xad\xaa\xe3\x98\x04\x8f\x12h^(p\xcd\x19h\xfe3\x171\x96\x93\xda\x16\xff\xec\xf6\xa7\x8e\xdb\xc3%\xdd\xa2\xeex\xa3\xf9\xdf\x8e\xef\xd4\x02\x99\xd9'
        autokey = tckey.autoconv_to_bytes(key)
        self.assertEqual(autokey, exp_bytes)
