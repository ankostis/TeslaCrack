#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import unicode_literals

from teslacrack import key as tckey
import unittest

import ddt
from future.builtins import str, int, bytes  # @UnusedImport

import itertools as itt


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
