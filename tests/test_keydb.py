#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import print_function, unicode_literals, division

from collections import OrderedDict
import logging
from os import path as osp
import tempfile
from teslacrack import __main__ as tcm, CrackException
from teslacrack import keydb
from schema import SchemaError
import unittest

from future import utils as futils
from future.builtins import str, int, bytes  # @UnusedImport

from _tutils  import assertRaisesRegex
from teslacrack.keyconv import AKey


tcm.init_logging(level=logging.DEBUG)



class Tkeydb(unittest.TestCase):
    def test_load_non_existent(self):
        db = keydb.load('BADPATH')
        self.assertIsInstance(db, OrderedDict)
        self.assertEqual(len(db), 2, list(db))

    def test_load_no_sample(self):
        db = keydb.load('BADPATH', no_sample=True)
        self.assertIsInstance(db, OrderedDict)
        self.assertNotIn('keys', 'db', list(db))
        self.assertLessEqual(len(db), 2, list(db))

    @unittest.skipIf(futils.PY2, "Missing `tempfile.TemporaryDirectory`!"
            "  Watch https://github.com/PythonCharmers/python-future/issues/199")
    def test_store_sample(self):
        with tempfile.TemporaryDirectory() as td:
            dbpath = osp.join(td, 'tcdb.yml')
            tcdb1 = keydb.sample()
            tcdb1.store(dbpath)
            tcdb2 = keydb.load(dbpath)
            self.assertEqual(tcdb1, tcdb2)

    @unittest.skip("OVERWRITES USER's KEYS!!")
    def test_store_sample_AT_USER_DIR(self):
        tcdb1 = keydb.sample()
        tcdb1.store()
        tcdb2 = keydb.load()
        self.assertEqual(tcdb1, tcdb2)

    def test_add_key_simple(self):
        db = keydb.sample()
        nkeyrecs = len(db.keyrecs())
        db.add_keyrec(type='BTC')
        self.assertEqual(len(db.keyrecs()), nkeyrecs+1, db)

    def test_add_key_not_AKey(self):
        db = keydb.empty()
        with assertRaisesRegex(self, SchemaError, "should be instance of 'AKey'", msg=db):
            db.add_keyrec(prv='bad AKEY')

    @unittest.skipIf(futils.PY2, "Missing `tempfile.TemporaryDirectory`!"
            "  Watch https://github.com/PythonCharmers/python-future/issues/199")
    def test_add_key_master_child(self):
        with tempfile.TemporaryDirectory() as td:
            dbpath = osp.join(td, 'tcdb.yml')
            db = keydb.empty()
            mk = db.add_keyrec(type='BTC', name='master', prv=AKey(b'asdfdsfdsasfd'))
            self.assertEqual(mk['name'], 'master', mk)
            self.assertEqual(len(db.keyrecs()), 1, db)
            ck = db.add_keyrec(type='AES', master=mk, name='child')
            self.assertEqual(len(db.keyrecs()), 2, db)
            self.assertEqual(ck['type'], 'AES', ck)
            db.store(dbpath)


