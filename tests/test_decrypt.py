#! python
# -*- coding: UTF-8 -*-
#
# This is part of TeslaCrack..
#
# Copyright (C) 2016 Googulator
#
# TeslaCrack is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# TeslaCrack is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with TeslaCrack; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
"""
TestCases for teslacrack.

It needs a `bash` (cygwin or git-for-windows) because that was an easy way
to make files/dirs inaccessible, needed for TCs.
"""
from __future__ import print_function, unicode_literals, division

import argparse
import glob
import logging
from os import path as osp
import os
import sys
import unittest
import _tutils  # @UnusedImport

from teslacrack import __main__ as tcm, decrypt


tcm.init_logging(level=logging.INFO)

def chmod(mode, files):
    files = ' '.join("'%s'" % f for f in files)
    cmd = 'bash -c "chmod %s %s"' % (mode, files)
    ret = os.system(cmd)
    if ret:
        print("Bash-cmd `chmod` failed with: %s "
              "\n  TCs below may also fail, unless you mark manually `unreadable*` files!"
              % ret,
              file=sys.stderr)


class TDecrypt(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.chdir(osp.join(osp.dirname(__file__), 'teslafiles'))
        ## Mark unreadable-files.
        chmod('115', glob.glob('unreadable*'))


    @classmethod
    def tearDownClass(cls):
        ## UNMark unreadable-files.
        chmod('775', glob.glob('unreadable*'))
        os.chdir(osp.dirname(__file__))


    min_scanned_files = 16

    def setUp(self):
        """
        Delete all generated decrypted-files.

        Note that tests below should not modify git-files.
        """
        #
        skip_ext = ['.py', '.ccc', '.vvv', '.zzz']
        skip_files = ['bad_decrypted', 'README']
        for f in glob.glob('*'):
            if (osp.isfile(f) and
                    osp.splitext(f)[1] not in skip_ext and
                    not [sf for sf in skip_files if sf in f]):
                os.unlink(f)

    def test_statistics_normal(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        stats = decrypt.decrypt(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(
                badexisting_nfiles=1,
                badheader_nfiles=3,
                crypted_nfiles=12,
                decrypted_nfiles=7,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=0,
                scanned_nfiles=-1,
                skip_nfiles=2,
                tesla_nfiles=16,
                unknown_nfiles=2,
                visited_ndirs=8)

        self.assertEquals(stats, exp_stats)


    def test_statistics_fix_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        decrypt.decrypt(opts)
        opts.dry_run=True
        opts.fix=True
        stats = decrypt.decrypt(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                badheader_nfiles=3,
                crypted_nfiles=12,
                decrypted_nfiles=1,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=1,
                scanned_nfiles=-1,
                skip_nfiles=8,
                tesla_nfiles=16,
                unknown_nfiles=2,
                visited_ndirs=8)
        self.assertEquals(stats, exp_stats)


    def test_statistics_overwrite_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        decrypt.decrypt(opts)
        opts.dry_run=True
        opts.overwrite=True
        stats = decrypt.decrypt(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=0,
                    badheader_nfiles=3,
                    crypted_nfiles=12,
                    decrypted_nfiles=9,
                    deleted_nfiles=0,
                    failed_nfiles=2,
                    ndirs=-1,
                    noaccess_ndirs=1,
                    overwrite_nfiles=9,
                    scanned_nfiles=-1,
                    skip_nfiles=0,
                    tesla_nfiles=16,
                    unknown_nfiles=2,
                    visited_ndirs=8)
        self.assertEquals(stats, exp_stats)


    def test_statistics_delete_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        decrypt.decrypt(opts)
        opts.dry_run=True
        opts.delete=True
        stats = decrypt.decrypt(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                badheader_nfiles=3,
                crypted_nfiles=12,
                decrypted_nfiles=0,
                deleted_nfiles=0,
                failed_nfiles=2,
                ndirs=-1,
                noaccess_ndirs=1,
                overwrite_nfiles=0,
                scanned_nfiles=-1,
                skip_nfiles=9,
                tesla_nfiles=16,
                unknown_nfiles=2,
                visited_ndirs=8)
        self.assertEquals(stats, exp_stats)


    def test_statistics_delete_old_dryrun(self):
        opts = argparse.Namespace(delete=False, delete_old=False, dry_run=False,
                fix=False, fpaths=['.'], overwrite=False, progress=False,
                verbose=True)
        decrypt.decrypt(opts)
        opts.dry_run=True
        opts.delete_old=True
        stats = decrypt.decrypt(opts)
        self.assertGreater(stats.scanned_nfiles, self.min_scanned_files)
        stats.scanned_nfiles = -1 ## arbitrary
        #print(stats)
        exp_stats = argparse.Namespace(badexisting_nfiles=1,
                    badheader_nfiles=3,
                    crypted_nfiles=12,
                    decrypted_nfiles=0,
                    deleted_nfiles=9,
                    failed_nfiles=2,
                    ndirs=-1,
                    noaccess_ndirs=1,
                    overwrite_nfiles=0,
                    scanned_nfiles=-1,
                    skip_nfiles=9,
                    tesla_nfiles=16,
                    unknown_nfiles=2,
                    visited_ndirs=8)
        self.assertEquals(stats, exp_stats)


