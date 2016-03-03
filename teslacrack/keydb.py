# This is part of TeslaCrack.
#
# Copyright (C) 2016 Googulator
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
"""
Maintain a db of key-records in a *yaml* textual format.

The *key-record* is the fundamental storage unit::

    type:        ( BTC | AES )
    pub:         ECDH public
    prv:         ECDH private, the AES-session or the private-BTC keys
    mul:         this is factorized to reconstruct keys
    primes:      list of primes (from factordb.com)
    composites:  list of 2-tuples: (<non-prime>, <factordb-status>)
    master:      master-children relationship
    name:
    desc:

The master-children relation is between btc <-- aes keys,
implemented with yaml's *Anchor* (in parent) and *Aliases* (in children).

See :func:`sample()` for example data.
"""
from __future__ import print_function, unicode_literals, division

from collections import OrderedDict
import io
import logging
from os import path as osp
import os
import shutil

import yaml

import functools as ft

from . import CrackException


log = logging.getLogger(__name__)


_db_verfld = '_db_schema_ver'
_db_version = '1'
_id = 'id'
_ref = 'ref'
_type_fld = 'type'
_master_fld = 'master'

def _safe_unlink(fpath):
    try:
        os.unlink(fpath)
    except Exception as ex:
        log.warning('While deleting file(%s): %r' %(fpath, ex))


def default_db_path():
    return osp.expanduser('~/.teslacrack.yml')


def _fix_version(db):
    file_version = db.get(_db_verfld, _db_version)
    if file_version != _db_version:
        raise CrackException('Incompatible db-version(%s)!' % file_version)
    db[_db_verfld] = _db_version
    try:
        db.move_to_end(_db_verfld, last=False)
    except AttributeError: # PY2
        pass

    return db


def _validate_master(db, key_rec, master, heal=False):
    if master:
        if not isinstance(master, OrderedDict):
            if heal:
                master = key_rec[_master_fld] = OrderedDict(master)
            else:
                raise ValueError("Master key-record (%s) was not another key!" % master)
        if id(master) not in [id(key_rec) for key_rec in db.get('keys', ())]:
            if heal:
                db._ensure_keys().append(master)
            else:
                raise ValueError("Master key-record (%s) was not in the Key-records list!" % master)


def _validate_key_rec(db, key_rec, heal=False):
    all_key_flds = set('type master name desc pub mul prv primes composites'.split())
    rec_flds = set(key_rec.keys())
    extra_flds = (rec_flds - all_key_flds)
    if extra_flds:
        if heal:
            for fld in extra_flds:
                del key_rec[fld]
        else:
            raise ValueError("Unknown key-fields %r!" % extra_flds)
    ktype = key_rec.get(_type_fld)
    if ktype and ktype not in ('BTC', 'AES'):
        if heal:
            del key_rec[_type_fld]
        else:
            raise ValueError("Invalid field-type(%r)! \n  Must be one of: BTC or AES" % ktype)
    master = key_rec.get(_master_fld)
    if master and not isinstance(master, OrderedDict):
        if heal:
            key_rec[_master_fld] = OrderedDict(master)
        else:
            raise ValueError("Master relation-field (%s) was not another key!" % master)
    return db # Not really needed here.


def _yield_db_checks(db):
    """A check is a 3-tuple: ``( 'name', check_func(db):bool, heal_func(db):db )``."""
    global_db_checks = [
        ('db-data-type', lambda db: isinstance(db, OrderedDict),
                _KeyDb),
        ('version', lambda db: next(iter(db.items()))== (_db_verfld, _db_version),
                _fix_version),
    ]
    for c in global_db_checks:
        yield c
    for i, key_rec in enumerate(db.get('keys', ())):
        yield ('key-no-%i' % i,
                ft.partial(_validate_key_rec, key_rec=key_rec, heal=False),
                ft.partial(_validate_key_rec, key_rec=key_rec, heal=True))


def _heal_db(db):
    for name, check, heal in _yield_db_checks(db):
        ok = False
        try:
            ok = check(db)
        except Exception as ex:
            log.debug('While db-checking %r: %r', name, ex)
        if not ok:
            log.warn('Db-healing %r...', name)
            db = heal(db)
    return db


def _check_db(db):
    for name, check, _ in _yield_db_checks(db):
        if not check(db):
            raise CrackException('Db-checking %r failed!' % name)


def load(dbpath=None, no_sample=False):
    if not dbpath:
        dbpath = default_db_path()
    if osp.isfile(dbpath):
        with io.open(dbpath, 'rt', encoding='utf-8') as fd:
            db = yaml.load(fd)
    else:
        db = _KeyDb() if no_sample else sample()
    db = _heal_db(db)

    return db


def sample():
    master_rec = OrderedDict([
        ('name', 'key33'),
        (_type_fld, 'BTC'),
        ('desc', 'Fully factored (both BTC "master" and AES session" keys).'),
        ('pub', 9538446796470938829684731739639878188192719462398500944849302506305979954739310262871148436514908439724826407676788293770514720299757719404545760627844148),
        ('mul', 'Jvh8Yz8fK8eiQR8t8OHaDyrA/Zc81WyyhzB1FBLVgGqkL8iRBzZ0uniTd0ESb7d4yk5XgGN0MRgHOXr3rf9bTg=='),
        ('prv', '9F0E6C608AFF777F1231D1D691FB0FFE8BF20CEC13ECBBCBA4992E51348462F2'),
        ('primes', [2, 3, 3, 3, 3, 653, 30593, 2536198376473, 14750956432784909988369359,
            35611703795037623446642023140478610781,
            473379042095770498166803972432242507015417089299862806179460011953993]),
    ])
    child_rec = OrderedDict([
        ('name', 'key33'),
        (_type_fld, 'AES'),
        (_master_fld, master_rec),
        ('pub', '0xae7e9af92984a795351524c3243eb641cd031346a7a9d4744b2b1b22fd6ef4e153fa8117048c11522ba4a0b909c36b3d4146cb6f137882dfa2b2de6f26f0598d'),
        ('mul', r'\x02[\x96\xa3\xf9\xab\x13u>\xd8F\x94\x03D"!l\x03\xfd\x02\x98\xe6}\x87\xe9\xb1\xac\xe8\x02}lP\xf0,\xfd\x14rGh\xae\xa2\xbe-Spva\xb5T\xa8\xd5\xea\xfa\r\\\xf3\xc3\xf2\xf2\x99\xe6\x14\x87\x0f'),
        ('prv', '79E263D45D5D7D2B576307116B31680DECE84E59562DAAA0BF93A5A0D34C9DED'),
        ('primes', [5, 5, 5, 31, 59, 1506317, 1615181, 32339941, 122098624903,
                521215182980524891501, 790355274904991699508542726894030536679239,
                136479699905329522235449077339883560021814719121773623]),
    ])
    db = _KeyDb([
        (_db_verfld, _db_version),
        ('keys', [
            master_rec, child_rec,
            OrderedDict([
                (_type_fld, 'BTC'),
                ('pub', 'E52+Luq5WeTW6lTmI4MjPXEHqgV3XkwIfIxIwb0Sy/ydMOtxy+HhUiwUd5/RZruhW4umSAc09jCl97JUa77o+w=='),
                ('mul', 'KHQR0t3D7M+C2EeTGjXSYBodzFJO0Z3urwAHf5ypK8QKbDUw4H7V/IVPfbUhRkj9DJYz326hCU0JyL/CXj3a0A=='),
                ('primes', [2, 2, 2, 2, 5, 7, 13, 23, 103]),
                ('composites', OrderedDict([
                        (122850342280668807673432007899874804879290282016547868470070085463593989252647008218227958129782893091689947159691338031444544438519788235585328939, 'CF'),
                ])),
            ]),
        ]),
    ])
    return db

def empty():
    return _KeyDb({_db_verfld: _db_version})


class _KeyDb(OrderedDict):


    def store(self, dbpath=None, debug=False):
        _check_db(self)
        if not dbpath:
            dbpath = default_db_path()
        b, f = osp.split(dbpath)
        tmp_dbpath = osp.join(b, '~%s.%s' % (f, os.getpid()))
        ok = False
        try:
            with io.open(tmp_dbpath, 'wt', encoding='utf-8') as fd:
                yaml.dump(self, fd,
                        encoding='utf-8',
                        allow_unicode=True,
                        indent=2,
                        tags=False,
                        version=[1,2])
            if osp.isfile(dbpath):
                bak_dbpath = dbpath + '.BAK'
                try:
                    shutil.copy(dbpath, bak_dbpath)
                except Exception as ex:
                    log.warning('Failed backing-up old self: %r-->%r',
                            dbpath, tmp_dbpath)
            shutil.move(tmp_dbpath, dbpath)
            ok = True
        finally:
            if not ok and not debug:
                _safe_unlink(tmp_dbpath)

    def _ensure_keys(self):
        keys = self.get('keys')
        if keys is None:
            keys = self['keys'] = []
        return keys

    def add_key(self, type=None, master=None, name=None, desc=None,
            pub=None, mul=None, prv=None, primes=None, composites=None):
        """Use the return value as a "master" for a subsequent key."""
        key_rec = OrderedDict((k, v) for k, v in zip(
                [_type_fld, _master_fld, 'name', 'desc', 'pub', 'mul', 'prv', 'primes', 'composites'],
                [type, master, name, desc, pub, mul, prv, primes, composites] )
                if v)
        _validate_key_rec(self, key_rec)
        self._ensure_keys().append(key_rec)
        return key_rec


yaml.add_representer(OrderedDict, lambda dumper, data:
        dumper.represent_dict(data.items()))
yaml.add_representer(_KeyDb, lambda dumper, data:
        dumper.represent_dict(data.items()))
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        lambda loader, node: OrderedDict(loader.construct_pairs(node)))

