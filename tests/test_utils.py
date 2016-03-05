#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import print_function, unicode_literals, division

import doctest
import logging
from teslacrack import __main__ as tcm, utils, keyconv
import unittest

import ddt
from future import utils as futils
from future.builtins import str, int, bytes  # @UnusedImport

from _tutils import assertRaisesRegex


tcm.init_logging(level=logging.DEBUG)



@unittest.skipIf(futils.PY2, "Doctests are made for py >= 3.3")
class Doctest(unittest.TestCase):

    def test_doctests(self):
        failure_count, test_count = doctest.testmod(
            utils,
            optionflags=doctest.NORMALIZE_WHITESPACE)  # | doctest.ELLIPSIS)
        self.assertGreater(test_count, 0, (failure_count, test_count))
        self.assertEquals(failure_count, 0, (failure_count, test_count))



class C(utils.MatchingDict, dict):
    def __init__(self, *args, **kwds):
        utils.MatchingDict.__init__(self, utils.words_with_prefix)
        self.update(dict(*args, **kwds))

@ddt.ddt
class TMatchingDict(unittest.TestCase):
    @ddt.data('ab', 'abc', 'df')
    def test_contains_EXACT(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertTrue(c.containsMatched(k))
        self.assertIn(k, c)

    @ddt.data('', 'a', 'd')
    def test_contains_PREFIX(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertTrue(c.containsMatched(k))
        self.assertNotIn(k, c)

    @ddt.data('D', 'A', 1)
    def test_contains_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertFalse(c.containsMatched(k))
        self.assertNotIn(k, c, k)

    @ddt.data(
            ('ab', 2),
            ('abc', 1),
            ('df', 3),
            )
    def test_getone_EXACT(self, case):
        k, v = case
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertEqual(c[k], v)
        self.assertEqual(c.matchOne(k), v)

    @ddt.data(
            ('d', 3),
            )
    def test_getone_PREFIX(self, case):
        k, v = case
        c=C({'abc':1, 'ab':2, 'df':3})
        with self.assertRaises(KeyError):
            c[k]
        self.assertEqual(c.matchOne(k), v)

    @ddt.data('A', 'D', 1)
    def test_getone_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with assertRaisesRegex(self, KeyError, str(k)):
            c[k]

    @ddt.data('', 'a')
    def test_getone_MORE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        with self.assertRaises(KeyError):
            c[k]
        with assertRaisesRegex(self, KeyError, 'Prefix .+ matched'):
            c.matchOne(k)

    @ddt.data(
            ('ab',     {'abc':1,  'df':3}),
            ('abc',    {'ab':2,   'df':3}),
            ('df',      {'abc':1, 'ab':2}),
            )
    def test_delone_EXACT(self, case):
        k, d = case
        dd = {'abc':1, 'ab':2, 'df':3}
        c=C(dd)
        del c[k]
        self.assertDictEqual(c, d)

        c=C(dd)
        c.delMatched(k)
        self.assertDictEqual(c, d)

    @ddt.data(
            ('d',      {'abc':1,  'ab':2}),
            )
    def test_delone_PREFIX(self, case):
        k, d = case
        dd = {'abc':1, 'ab':2, 'df':3}
        c=C(dd)
        with self.assertRaises(KeyError):
            del c[k]
        c=C(dd)
        c.delMatched(k)
        self.assertDictEqual(c, d)

    @ddt.data('A', 'D', 1)
    def test_delone_NONE(self, k):
        dd = {'abc':1, 'ab':2, 'df':3}
        c=C(dd)
        with self.assertRaises(KeyError):
            del c[k]

        c=C(dd)
        with assertRaisesRegex(self, KeyError, str(k)):
            c.delMatched(k)

    @ddt.data('', 'a')
    def test_delone_MORE(self, k):
        dd = {'abc':1, 'ab':2, 'df':3}
        c=C(dd)
        with self.assertRaises(KeyError):
            c[k]

        c=C(dd)
        with assertRaisesRegex(self, KeyError, 'Prefix .+ matched'):
            c.delMatched(k)

    @ddt.data(
            ('',    {'abc':1, 'ab':2, 'df':3}),
            ('a',   {'abc':1, 'ab':2}),
            ('ab',  {'abc':1, 'ab':2}),
            ('d',   {'df':3}),
            ('df',  {'df':3}),
            )
    def test_getall_OK(self, case):
        k, v = case
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertDictEqual(dict(c.matchAll(k)), v)

    @ddt.data('A', 'D', 1)
    def test_getall_NONE(self, k):
        c=C({'abc':1, 'ab':2, 'df':3})
        self.assertEqual(c.matchAll(k), [])

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
        self.assertEqual(c.delAll(k), len(dd) - len(d))
        self.assertDictEqual(c, d)

    @ddt.data('A', 'D', 1)
    def test_delall_NONE(self, k):
        d = {'abc':1, 'ab':2, 'df':3}
        c=C(d)
        self.assertEqual(c.delAll(k), 0)
        self.assertDictEqual(c, d)

