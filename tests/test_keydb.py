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
from pprint import pprint
import tempfile
from teslacrack import __main__ as tcm, CrackException
from teslacrack import keydb
from teslacrack.keyconv import AKey
import unittest

import ddt
from future import utils as futils
from future.builtins import str, int, bytes  # @UnusedImport
from schema import SchemaError

from _tutils import assertRaisesRegex


tcm.init_logging(level=logging.DEBUG)

_test_dbpath = '~/.teslacrack-test.yaml'
_all_dbkeys = [
            9538446796470938829684731739639878188192719462398500944849302506305979954739310262871148436514908439724826407676788293770514720299757719404545760627844148,
        '9538446796470938829684731739639878188192719462398500944849302506305979954739310262871148436514908439724826407676788293770514720299757719404545760627844148',
        'Jvh8Yz8fK8eiQR8t8OHaDyrA/Zc81WyyhzB1FBLVgGqkL8iRBzZ0uniTd0ESb7d4yk5XgGN0MRgHOXr3rf9bTg==',
        '9F0E6C608AFF777F1231D1D691FB0FFE8BF20CEC13ECBBCBA4992E51348462F2',
        '0xae7e9af92984a795351524c3243eb641cd031346a7a9d4744b2b1b22fd6ef4e153fa8117048c11522ba4a0b909c36b3d4146cb6f137882dfa2b2de6f26f0598d',
        '79E263D45D5D7D2B576307116B31680DECE84E59562DAAA0BF93A5A0D34C9DED',
        'E52+Luq5WeTW6lTmI4MjPXEHqgV3XkwIfIxIwb0Sy/ydMOtxy+HhUiwUd5/RZruhW4umSAc09jCl97JUa77o+w==',
        'KHQR0t3D7M+C2EeTGjXSYBodzFJO0Z3urwAHf5ypK8QKbDUw4H7V/IVPfbUhRkj9DJYz326hCU0JyL/CXj3a0A==',
        '\x02[\x96\xa3\xf9\xab\x13u>\xd8F\x94\x03D"!l\x03\xfd\x02\x98\xe6}\x87\xe9\xb1\xac\xe8\x02}lP\xf0,\xfd\x14rGh\xae\xa2\xbe-Spva\xb5T\xa8\xd5\xea\xfa\r\\\xf3\xc3\xf2\xf2\x99\xe6\x14\x87\x0f',
        b'\x02[\x96\xa3\xf9\xab\x13u>\xd8F\x94\x03D"!l\x03\xfd\x02\x98\xe6}\x87\xe9\xb1\xac\xe8\x02}lP\xf0,\xfd\x14rGh\xae\xa2\xbe-Spva\xb5T\xa8\xd5\xea\xfa\r\\\xf3\xc3\xf2\xf2\x99\xe6\x14\x87\x0f',
]
@ddt.ddt
class Tkeydb(unittest.TestCase):
    @unittest.skipIf(futils.PY2, "Missing `tempfile.TemporaryDirectory`!"
            "  Watch https://github.com/PythonCharmers/python-future/issues/199")
    def test_load_non_existent(self):
        with tempfile.TemporaryDirectory() as td:
            dbpath = osp.join(td, 'BADPATH')
            db = keydb.load(dbpath)
        self.assertIsInstance(db, OrderedDict)
        self.assertEqual(len(db), 2, list(db))

    @unittest.skipIf(futils.PY2, "Missing `tempfile.TemporaryDirectory`!"
            "  Watch https://github.com/PythonCharmers/python-future/issues/199")
    def test_load_no_sample(self):
        with tempfile.TemporaryDirectory() as td:
            dbpath = osp.join(td, 'BADPATH')
            db = keydb.load(dbpath)
        self.assertIsInstance(db, OrderedDict)
        self.assertNotIn('keys', 'db', list(db))
        self.assertLessEqual(len(db), 2, list(db))

    @unittest.skipIf(futils.PY2, "Missing `tempfile.TemporaryDirectory`!"
            "  Watch https://github.com/PythonCharmers/python-future/issues/199")
    def test_store_sample(self):
        with tempfile.TemporaryDirectory() as td:
            dbpath = osp.join(td, 'tcdb.yaml')
            tcdb1 = keydb.sample()
            tcdb1.store(dbpath)
            tcdb2 = keydb.load(dbpath)
            self.assertEqual(tcdb1, tcdb2)

    @unittest.skip("OVERWRITES USER's KEYS!!")
    def test_store_sample_AT_USER_DIR(self):
        tcdb1 = keydb.sample()
        tcdb1.store()
        tcdb2 = keydb.load(_test_dbpath)
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
            dbpath = osp.join(td, 'tcdb.yaml')
            db = keydb.empty()
            mk = db.add_keyrec(type='BTC', name='master', prv=AKey(b'asdfdsfdsasfd'))
            self.assertEqual(mk['name'], 'master', mk)
            self.assertEqual(len(db.keyrecs()), 1, db)
            ck = db.add_keyrec(type='AES', master=mk, name='child')
            self.assertEqual(len(db.keyrecs()), 2, db)
            self.assertEqual(ck['type'], 'AES', ck)
            db.store(dbpath)

    def test_keyring_sample_structure(self):
        db = keydb.load(_test_dbpath)
        krng = keydb.KeyRing(db)
        self.assertGreaterEqual(len(db), 2, db)
        self.assertGreater(len(krng._akeys_ii), 2, krng._akeys_ii)
        self.assertGreaterEqual(len(krng._names_ii), 2, krng._names_ii)

    @ddt.data(*_all_dbkeys
        #FAIL br'\x02[\x96\xa3\xf9\xab\x13u>\xd8F\x94\x03D"!l\x03\xfd\x02\x98\xe6}\x87\xe9\xb1\xac\xe8\x02}lP\xf0,\xfd\x14rGh\xae\xa2\xbe-Spva\xb5T\xa8\xd5\xea\xfa\r\\\xf3\xc3\xf2\xf2\x99\xe6\x14\x87\x0f',
        #FAIL r'\x02[\x96\xa3\xf9\xab\x13u>\xd8F\x94\x03D"!l\x03\xfd\x02\x98\xe6}\x87\xe9\xb1\xac\xe8\x02}lP\xf0,\xfd\x14rGh\xae\xa2\xbe-Spva\xb5T\xa8\xd5\xea\xfa\r\\\xf3\xc3\xf2\xf2\x99\xe6\x14\x87\x0f',
    )
    def test_match_keydb_by_keyprefix(self, dbkey):
        npref = 16
        prefix = int(str(dbkey)[:npref]) if isinstance(dbkey, int) else dbkey[:npref]
        db = keydb.sample()
        krng = keydb.KeyRing(db)
        keyrecs= krng._match_by_dbkeys([prefix], batch=0)
        #pprint(keyrecs)
        self.assertEqual(len(keyrecs), 1, (keyrecs, dbkey))
        kr = keyrecs[0]
        #self.assertIn(dbkey, (kr['pub'], kr['prv'], kr['mul']), (keyrecs, dbkey))

    @ddt.data(('name',2), ('type', 3), ('master', 1),
            ('pub', 3), ('mul', 3) ,('prv', 2),
            ('primes', 3),('composites', 1),
            ('errors', 0),('warns', 0),
            )
    def test_keyring_read(self, case):
        fld, nkrecs = case
        db = keydb.sample()
        krng = keydb.KeyRing(db)
        keyrecs = krng.get_keyrec_fields(fields=[fld])
        #pprint(keyrecs)
        self.assertEqual(len(keyrecs), nkrecs, keyrecs)
        for kr in keyrecs:
            self.assertEqual(len(kr), 1, kr)

    @ddt.data(*_all_dbkeys)
    def test_keyring_del_keyrec(self, dbkey):
        npref = 16
        prefix = int(str(dbkey)[:npref]) if isinstance(dbkey, int) else dbkey[:npref]
        db = keydb.sample()
        krng = keydb.KeyRing(db)
        nkrs = len(db.keyrecs())
        krng.del_keyrec_field([prefix], fields=(), batch=0, force=1)
        self.assertEqual(len(db.keyrecs()), nkrs-1, len(db.keyrecs()))

