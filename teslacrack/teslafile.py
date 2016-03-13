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
#
## Parse keys from tesla-files headers, impl `file` sub-cmd.
from __future__ import print_function, unicode_literals, division

from binascii import unhexlify
from collections import namedtuple, OrderedDict
import io
import logging
import os
import struct
import time

from future.builtins import str, int, bytes  # @UnusedImport
from toolz import dicttoolz

import os.path as osp

from . import CrackException
from .keyconv import AKey, lalign_bytes


log = logging.getLogger(__name__)

## Add more known extensions, e.g. '.xyz'.
#  Note that '.xxx', '.micro' and '.ttt' are crypted by a new variant
#  of teslacrypt (3.0).
tesla_extensions = ['.vvv', '.ccc',  '.zzz', '.aaa', '.abc']


def tesla_mul_to_bytes(hex_bkey):
    """Purposefully fails on odd-length keys, to detect corrupt tesla-headers."""
    return lalign_bytes(unhexlify(hex_bkey.rstrip(b'\0')))


tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

_header_fmt     = b'=5s 64s 130s 1x 64s 130s 16s 1I'
_header_len = struct.calcsize(_header_fmt)
assert _header_len == 414, _header_len

_bin_fields = ('start', 'btc_pub_key', 'aes_pub_key', 'iv')
_hex_fields = ('btc_mul_key', 'aes_mul_key')

_Header = namedtuple('_Header',
        'start  btc_pub_key  btc_mul_key  aes_pub_key  aes_mul_key  iv  size')

class Header(_Header):
    """
    Immutable teslafile header-fields converted to AKey instances.

    Use :method:`from_fd()` to construct it.
    """
    __slots__ = ()

    @classmethod
    def from_fd(cls, fd, conv=None, raw=False):
        """
        Reads a tesla-file's header, checks its validity and converts.

        :param fd:
                a file-descriptor freshly opened in binary mode on a tesla-file.
        :param str conv:
                the default feild-conversions (see :class:`AKey`).
        :return:
            a :data:`Header` named-tuple
        """
        fname = lambda: getattr(fd, 'name', '<unknown>')
        hbytes = fd.read(_header_len)
        magic_ok = any(hbytes.startswith(tmg) for tmg in tesla_magics)
        headerlen_ok = len(hbytes) >= _header_len
        if not (headerlen_ok and magic_ok):
            raise CrackException("Tesla-file(%r) doesn't appear to be TeslaCrypted! "
                    "\n  magic-bytes(%r) OK? %s, file-size(%i, minimum: %i) OK? %s." % (
                            fname(),
                            bytes(hbytes[:5]), magic_ok,
                            len(hbytes), _header_len, headerlen_ok))
        try:
            h = cls._make(struct.unpack(_header_fmt, hbytes))
            if not raw:
                h = h._fix_raw(conv)
        except Exception as ex:
            raise CrackException("Tesla-file(%r)'s keys might be corrupted: %s" %
                    (fname(), ex))
        return h

    def __repr__(self):
        return '\n'.join('%15.15s: %r' % (k, v)
                for k, v in self._asdict().items())

    def __str__(self):
        return '\n'.join('%15.15s: %s' %
                (k, v.conv() if k != 'size' else v)
                for k, v in self._asdict().items())

    def _fix_raw(self, conv=None):
        return self._replace(
            start=AKey(self.start, conv),
            btc_pub_key=AKey(self.btc_pub_key, conv),
            btc_mul_key=AKey(tesla_mul_to_bytes(self.btc_mul_key), conv),
            aes_pub_key=AKey(self.aes_pub_key, conv),
            aes_mul_key=AKey(tesla_mul_to_bytes(self.aes_mul_key), conv),
            iv=AKey(self.iv, conv),
        )


    def conv(self, conv):
        for f in self:
            if isinstance(f, AKey):
                f._conv = conv


    def fields_by_substr_list(self, substr_list=()):
        """
        :rtype: OrderedDict
        """
        if not substr_list:
            return self._asdict()
        return dicttoolz.keyfilter(lambda k: any(ss in k for ss in substr_list),
                self._asdict(), OrderedDict)


def conv_fields(h, conv):
    if isinstance(h, Header):
        h = h._asdict()
    return OrderedDict((k, v.conv(conv) if k not in ('size', 'file') else v)
            for k, v in h.items())


def match_substr_to_fields(substr_list):
    fields = ([fld for fld in Header._fields for s in substr_list if s.lower() in fld.lower()]
            if substr_list else Header._fields)
    if not fields:
        raise CrackException("Field-substr %r matched no header-field: %r"
                "\n  Must be any case-insensitive substring of: %r" %
                (substr_list, list(fields), Header._fields))
    return fields


def fetch_file_headers(fpaths, fields=None, conv=None):
    if not fields:
        fields = Header._fields
    elif set(fields) > set(Header._fields):
        raise CrackException('Invalid Header-fields: %r \n  Must be one of: %r' %
                (set(fields) - set(Header._fields), list(Header._fields)))

    res = []
    def process_header(file):
        try:
            if osp.splitext(file)[1] in tesla_extensions:
                with io.open(file, 'rb') as fd:
                    h = Header.from_fd(fd)

                h = dicttoolz.keyfilter(lambda k: k in fields, h._asdict(),
                        lambda: OrderedDict(file=file))
                if conv:
                    h = conv_fields(h, conv)
                res.append(h)
        except Exception as ex:
            log.warning("File %r: %s", file, ex)

    traverse_fpaths(fpaths, process_header)
    return res


PROGRESS_INTERVAL_SEC = 3 # Log stats every that many files processed.
_last_progress_time = 0#time.time()

def is_progess_time():
    global _last_progress_time
    if time.time() - _last_progress_time > PROGRESS_INTERVAL_SEC:
        _last_progress_time = time.time()
        return True


def traverse_fpaths(fpaths, file_processor, log_progress=None, stats=None):
    """Scan disk and decrypt tesla-files.

    :param: list fpaths:
            Start points to scan.
            Must be unicode, and on *Windows* '\\?\' prefixed.
    :param: callable proc_file_func:
            A function: ``file_processor(fpath)``
    """
    def handle_bad_subdir(err):
        stats.noaccess_ndirs += 1
        log.error('%r: %s' % (err, err.filename))

    try:
        from unittest import mock  # @UnusedImport
    except ImportError:
        import mock # @UnresolvedImport @Reimport
    if not stats:
        stats = mock.MagicMock()
    if not log_progress:
        log_progress = mock.MagicMock()

    for fpath in fpaths:
        if osp.isfile(fpath):
            file_processor(fpath)
        else:
            for dirpath, _, files in os.walk(fpath, onerror=handle_bad_subdir):
                stats.visited_ndirs += 1
                stats.scanned_nfiles += len(files)
                if is_progess_time():
                    log_progress(dirpath)
                for f in files:
                    file_processor(osp.join(dirpath, f))


def count_subdirs(fpaths):
    n = 0
    log.info("+++Counting dirs...")
    for f in fpaths:
        #f = upath(f) # Don't bother...
        for _ in os.walk(f):
            if is_progess_time():
                log.info("+++Counting dirs: %i...", n)
            n += 1
    return n


