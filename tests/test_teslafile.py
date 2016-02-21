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
from __future__ import print_function, unicode_literals

from os import path as osp
import unittest

from teslacrack import teslafile, CrackException
from teslacrack import __main__ as tcm

try:
    assertRaisesRegex = unittest.TestCase.assertRaisesRegex
except AttributeError:
    assertRaisesRegex = unittest.TestCase.assertRaisesRegexp #PY2

tcm.init_logging()

def _tf_fpath(fname):
    return osp.join(osp.dirname(__file__), 'teslafiles', fname)


class TTeslafile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg.


    def test_reading_invalid_tesla_file_smaller(self):
        f = 'tesla_smaller_size.jpg.vvv'
        with open(_tf_fpath(f), 'rb') as fd:
            with assertRaisesRegex(self, CrackException,
                    ' magic-bytes.+ OK\\? True, file-size.+ OK\\? False'):
                teslafile.parse_tesla_header(fd)

    def test_reading_invalid_tesla_file_bad_magic(self):
        f = 'tesla_invalid_magic.pdf.ccc'
        with open(_tf_fpath(f), 'rb') as fd:
            with assertRaisesRegex(self, CrackException,
                    ' magic-bytes.+ OK\\? False, file-size.+ OK\\? True'):
                teslafile.parse_tesla_header(fd)
