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
from __future__ import print_function, unicode_literals, division

import unittest

try:
    assertRegex = unittest.TestCase.assertRegex
    assertNotRegex = unittest.TestCase.assertNotRegex
    assertRaisesRegex = unittest.TestCase.assertRaisesRegex
    from unittest.mock import patch  # @UnusedImport
    from unittest import mock  # @UnusedImport
except AttributeError:
    ## PY2
    assertRegex = unittest.TestCase.assertRegexpMatches
    assertNotRegex = unittest.TestCase.assertNotRegexpMatches  # @UndefinedVariable
    assertRaisesRegex = unittest.TestCase.assertRaisesRegexp
    import mock  # @UnresolvedImport @UnusedImport @Reimport
    from mock import patch  # @UnresolvedImport @UnusedImport @Reimport
