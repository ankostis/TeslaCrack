#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import unicode_literals

import io
import os
import re
import unittest

from teslacrack import __main__ as tcm
import teslacrack


try:
    from unittest.mock import patch
except ImportError:
    from mock import patch



mydir = os.path.dirname(__file__)
readme_path = os.path.join(mydir, '..', 'README.rst')


class Doctest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg.


    def test_README_version_opening(self):
        ver = teslacrack.__version__
        header_len = 20
        mydir = os.path.dirname(__file__)
        with open(readme_path) as fd:
            for i, l in enumerate(fd):
                if ver in l:
                    break
                elif i >= header_len:
                    msg = "Version(%s) not found in README %s header-lines!"
                    raise AssertionError(msg % (ver, header_len))


    def test_README_version_from_cmdline(self):
        mydir = os.path.dirname(__file__)
        with open(readme_path) as fd:
            ftext = fd.read().decode('utf-8')
            with patch('sys.stdout', new=io.StringIO()) as stdout:
                try:
                    tcm.main(b'--version')
                except SystemExit as ex:
                    pass ## Cancel docopt's exit()
            ver_str = stdout.getvalue().strip()
            assert ver_str
            regex = 'teslacrack-([^ ]+)'
            m = re.match(regex, ver_str)
            self.assertIsNotNone(m, 'Version(%s) not found in: \n%s' % (
                    regex, ver_str))
            proj_ver = m.group(1)
            self.assertIn(proj_ver, ftext,
                          "Version(%s) not found in README cmd-line version-check!" %
                          proj_ver)


    def test_README_relDate(self):
        reldate = teslacrack.__updated__
        mydir = os.path.dirname(__file__)
        with open(readme_path, 'rt') as fd:
            ftext = fd.read().decode('utf-8')
            self.assertIn(reldate, ftext,
                          "Reldate(%s) not found in README!" % reldate)


    def test_README_contains_main_help_msg(self):
        help_msg = tcm.__doc__  # @UndefinedVariable
        mydir = os.path.dirname(__file__)
        with open(readme_path) as fd:
            ftext = fd.read().decode('utf-8')
            msg = "Main help-line[%s] missing from README: \n  %s"
            for i, l in enumerate(help_msg.split('\n')):
                l = l.strip()
                if l:
                    assert l in ftext, msg % (i, l)
