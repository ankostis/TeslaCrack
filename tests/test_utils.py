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

