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
Maintain the *keyring* backed by a a db of key-records in a *yaml* textual format.

The *key-record* is the fundamental storage unit::

    name:
    desc:
    type:        ( BTC | AES )
    master:      master-children relationship
    pub:         ECDH public
    mul:         this is factorized to reconstruct keys
    prv:         ECDH private, the AES-session or the private-BTC keys
    btc_addr:
    primes:      list of primes (from factordb.com)
    composites:  list of 2-tuples: (<non-prime>, <factordb-status>)
    files:
    errors:
    warns:

The master-children relation is between btc <-- aes keys,
implemented with yaml's *Anchor* (in parent) and *Aliases* (in children).

See :func:`sample()` for example data.

The *keyring* is an index allowing traversing matched keys.
"""
from __future__ import print_function, unicode_literals, division

from collections import OrderedDict
import io
import logging
from os import path as osp
import os
import shutil

from boltons.setutils import IndexedSet as iset
from future.builtins import str, int, bytes as newbytes  # @UnusedImport
from schema import (
    SchemaError, Schema, And, Or, Use, Optional as Opt)
import yaml

import functools as ft
from past.builtins import basestring
from . import CrackException
from .keyconv import AKey


log = logging.getLogger(__name__)


_db_verfld = '_db_schema_ver'
_db_version = '1'
_master_fld = 'master'
_keyrec_fields = ['name', 'type', _master_fld, 'pub', 'mul', 'prv', 'btc_addr',
                        'primes', 'composites', 'files', 'error', 'warn', 'desc']
_AKey_fields = ['pub', 'mul', 'prv']

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


def _reorder_dict(dic, proto):
    """Can heal order only if OrderedDict (not to break any  parent-containers)."""
    assert isinstance(dic, OrderedDict)
    seq = iset(dic)
    proto = iset(proto)
    ordseq = (proto & seq)
    if seq != ordseq:
        for k in ordseq:
            dic[k] = dic.pop(k)
    _check_ordered(dic, proto)
    return dic


def _check_ordered(seq, proto):
    """Raises if oreder of `seq` not as `proto` (minus any missing elements."""
    seq = iset(seq)
    proto = iset(proto)
    assert seq == (proto & seq), 'Unsorted %r != %r!' % (seq, proto)
    return True


#########################
## Schema lib.
#########################
class Tuple(object):

    def __init__(self, *args, **kw):
        self._args = args
        assert list(kw) in (['error'], [])
        self._error = kw.get('error')

    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(repr(a) for a in self._args))

    def validate(self, data):
        schemas = [Schema(s, error=self._error) for s in self._args]
        if len(data) != len(schemas):
            raise SchemaError('Data-length(%i) != Tuple-length(%i), data:%r' %
                    (len(data), len(schemas), data), self._error)
        return type(data)(s.validate(d) for s, d in zip(schemas, data))
#########################


def _make_keyrec_schema(db, heal):
    from . import factordb

    Str = Use(str) if heal else basestring
    Int = Use(int) if heal else int
    AAKey = Use(AKey.auto) if heal else AKey
    schema = Schema(And(
        ft.partial(_reorder_dict if heal else _check_ordered, proto=_keyrec_fields),
        {
            Opt('name'):        Str,
            Opt('desc'):        Str,
            Opt('type'):        Or('BTC', 'AES'),
            Opt('pub'):         AAKey,
            Opt('mul'):         AAKey,
            Opt('prv'):         AAKey,
            Opt('btc_addr'):    Str,
            Opt('primes'):      [Int],
            Opt('composites'):  [Tuple(int, Or(*factordb._factor_statuses))],
            Opt('files'):       [Str],
            Opt('error'):       Str,
            Opt('warn'):        Str,
        },
    ))
    schema._schema._args[1][Opt('master')] = Schema(And(
#             lambda v: id(v) in [id(kr) for kr in db.get('keys', ())], ## Check in keys before rewritting it.
            schema,  ## Recursive
    ))
    return schema


def _make_db_schema(db, heal):
    if heal:
        _fix_version(db)
    schema = Schema(And(_KeyDb, {
        '_db_schema_ver': And(str, '1'),
        Opt('keys'): [_make_keyrec_schema(db, heal)]
    }))
    return schema


def heal_db(db):
    schema = _make_db_schema(db, heal=True)
    return schema.validate(db)

def check_db(db):
    schema = _make_db_schema(db, heal=False)
    schema.validate(db)


def load(dbpath=None, no_sample=False):
    if not dbpath:
        dbpath = default_db_path()
    if osp.isfile(dbpath):
        with io.open(dbpath, 'rt', encoding='utf-8') as fd:
            db = _KeyDb(yaml.load(fd)) ##TODO Remove
    else:
        db = _KeyDb() if no_sample else sample()
    assert isinstance(db, _KeyDb)
    db = heal_db(db)

    return db


def sample():
    master_rec = OrderedDict([
        ('name', 'key33'),
        ('type', 'BTC'),
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
        ('type', 'AES'),
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
                ('type', 'BTC'),
                ('pub', 'E52+Luq5WeTW6lTmI4MjPXEHqgV3XkwIfIxIwb0Sy/ydMOtxy+HhUiwUd5/RZruhW4umSAc09jCl97JUa77o+w=='),
                ('mul', 'KHQR0t3D7M+C2EeTGjXSYBodzFJO0Z3urwAHf5ypK8QKbDUw4H7V/IVPfbUhRkj9DJYz326hCU0JyL/CXj3a0A=='),
                ('primes', [2, 2, 2, 2, 5, 7, 13, 23, 103]),
                ('composites', [
                        (122850342280668807673432007899874804879290282016547868470070085463593989252647008218227958129782893091689947159691338031444544438519788235585328939,
                        'CF'),
                ]),
            ]),
        ]),
    ])
    return heal_db(db)

def empty():
    return _KeyDb({_db_verfld: _db_version})


class _KeyDb(OrderedDict):


    def store(self, dbpath=None, debug=False):
        check_db(self)
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
                    log.warning("Failed backing-up old KeyDB due to: %s \n  %r-->%r",
                            ex, dbpath, tmp_dbpath)
            shutil.move(tmp_dbpath, dbpath)
            ok = True
        finally:
            if not ok and not debug:
                _safe_unlink(tmp_dbpath)

    def keyrecs(self):
        keys = self.get('keys')
        if keys is None:
            keys = self['keys'] = []
        return keys

    def add_keyrec(self, type=None, master=None, name=None, desc=None,  # @ReservedAssignment
            pub=None, mul=None, prv=None, btc_addr=None, primes=None, composites=None,
            files=None, error=None, warn=None):
        """Use the return value as a "master" for a subsequent key."""
        fields = {k:v for k,v in locals().items() if v is not None and k}
        del fields['self'];
        keyrec = _reorder_dict(OrderedDict(fields), _keyrec_fields)
        self.keyrecs().append(keyrec)

        schema = _make_keyrec_schema(self, heal=False)
        keyrec = schema.validate(keyrec)

        return keyrec


yaml.add_representer(OrderedDict, lambda dumper, data:
        dumper.represent_dict(data.items()))
yaml.add_representer(_KeyDb, lambda dumper, data:
        dumper.represent_dict(data.items()))
yaml.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        lambda loader, node: OrderedDict(loader.construct_pairs(node)))

