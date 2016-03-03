#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import print_function, unicode_literals, division

import logging
from teslacrack import __main__ as tcm, utils
import unittest

import ddt
from future.builtins import str, int, bytes  # @UnusedImport

from _tutils import assertRaisesRegex


tcm.init_logging(level=logging.DEBUG)



class C(utils.PrefixDictMixin, dict):
    pass

@ddt.ddt
class TPrefixDictMixin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.

    @ddt.data('', 'a', 'ab', 'abc', 'd', 'df')
    def test_contains_OK(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertIn(k, c)

    @ddt.data('D', 'A', 1)
    def test_contains_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertNotIn(k, c, k)

    @ddt.data(
            ('ab', 2),
            ('abc', 1),
            ('d', 3),
            ('df', 3),
            )
    def test_get_OK(self, case):
        k, v = case
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertEqual(c[k], v)

    @ddt.data('A', 'D', 1)
    def test_get_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with assertRaisesRegex(self, KeyError, str(k)):
            c[k]

    @ddt.data('', 'a')
    def test_get_MORE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with assertRaisesRegex(self, KeyError, 'Prefix .+ matched'):
            c[k]

    @ddt.data(
            ('ab',     {'abc':1,  'df':3}),
            ('abc',    {'ab':2,   'df':3}),
            ('d',      {'abc':1,  'ab':2}),
            ('df',      {'abc':1, 'ab':2}),
            )
    def test_del_OK(self, case):
        k, d = case
        c=C({'abc':1, 'ab':2, 'df':3})
        del c[k]
        self.assertDictEqual(c, d)

    @ddt.data('A', 'D', 1)
    def test_del_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with assertRaisesRegex(self, KeyError, str(k)):
            del c[k]

    @ddt.data('', 'a')
    def test_del_MORE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with assertRaisesRegex(self, KeyError, 'Prefix .+ matched'):
            c[k]

    @ddt.data(
            ('', (1,2,3)),
            ('a', (1,2)),
            ('ab', (1,2)),
            ('d', (3,)),
            ('df', (3,)),
            )
    def test_getall_OK(self, case):
        k, v = case
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertSetEqual(set(c.getall(k)), set(v))

    @ddt.data('A', 'D', 1)
    def test_getall_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertEqual(c.getall(k), [])

    @ddt.data(
            ('a',      {'df':3}),
            ('ab',     {'df':3}),
            ('abc',    {'ab':2, 'df':3}),
            ('d',      {'abc':1, 'ab':2}),
            ('df',      {'abc':1, 'ab':2}),
            )
    def test_delall_OK(self, case):
        k, d = case
        dd = {'abc':1, 'ab':2, 'df':3}
        c=C(dd)
        self.assertEqual(c.delall(k), len(dd) - len(d))
        self.assertDictEqual(c, d)

    @ddt.data('A', 'D', 1)
    def test_delall_NONE(self, k):
        d = {'abc':1, 'ab':2, 'df':3}
        c=C(d)
        self.assertEqual(c.delall(k), 0)
        self.assertDictEqual(c, d)

