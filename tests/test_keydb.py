#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import print_function, unicode_literals, division

import logging
from teslacrack import __main__ as tcm, keydb
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch


import ddt
from future.builtins import str, int, bytes  # @UnusedImport

import itertools as itt


tcm.init_logging(level=logging.DEBUG)

_factorized_num = 2118716315081944071154463906483768844885801576547629834952739116332490288727711150774189198852837304785074169499127916918462675640932594243139970187254480
_factorized_num_factors = [
         2, 2, 2, 2, 5, 7, 13, 23, 103,
        122850342280668807673432007899874804879290282016547868470070085463593989252647008218227958129782893091689947159691338031444544438519788235585328939
]

_factordb_search = {
    _factorized_num: b"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
        <form action="index.php" method="get">
        <center>
        <input type="text" size=100 name="query" value="2118716315081944071154463906483768844885801576547629834952739116332490288727711150774189198852837304785074169499127916918462675640932594243139970187254480">
        <input type="submit" value="Factorize!"> &nbsp; (<a href="help.php?page=0">?</a>)
        </center>
        <br /><br />
        </form><table border=0 width="98%"><tr><td align="center" colspan=3 bgcolor="#BBBBBB"><b>Result:</b></td>
        </tr><tr><td bgcolor="#DDDDDD">status <a href="status.html" target="_blank">(?)</a></td>
        <td bgcolor="#DDDDDD">digits</td>
        <td bgcolor="#DDDDDD">number</td>
        </tr><tr><td>CF</td>
        <td>154 <a href="index.php?showid=1100000000820004790">(show)</a></td>
        <td><a href="index.php?id=1100000000820004790"><font color="#002099">2118716315...80</font></a><sub>&lt;154&gt;</sub> = <a href="index.php?id=2"><font color="#000000">2^4</font></a> &middot; <a href="index.php?id=5"><font color="#000000">5</font></a> &middot; <a href="index.php?id=7"><font color="#000000">7</font></a> &middot; <a href="index.php?id=13"><font color="#000000">13</font></a> &middot; <a href="index.php?id=23"><font color="#000000">23</font></a> &middot; <a href="index.php?id=103"><font color="#000000">103</font></a> &middot; <a href="index.php?id=1100000000820004792"><font color="#002099">1228503422...39</font></a><sub>&lt;147&gt;</sub></td>
        </tr></table><br><br><div id="moreinfo"><table border=0 width="98%"><tr><td align="center" bgcolor="#BBBBBB"><b>More information</b> <a onclick="getdata('moreinfo','frame_moreinfo.php?id=1100000000820004790')"><img src="expand.png" border=0></a></td>
        </tr></table></div><br /><div id="ecm"><table border=0 width="98%"><tr><td align="center" bgcolor="#BBBBBB"><b>ECM</b> <a onclick="getdata('ecm','frame_ecm.php?id=1100000000820004790')"><img src="expand.png" border=0></a></td>
        </tr></table></div><br /><form action="index.php?id=1100000000820004790" method="POST"><center><table border=0 width="800"><tr><td align="center" bgcolor="#BBBBBB"><b>Report factors</b></td>
        </tr><tr><td align="center" bgcolor="#DDDDDD"><textarea name="report" rows=4 cols=110></textarea></td>
        </tr><tr><td align="center">Format: <select name="format" size=1>
        <option value="0">Auto detect (slow)
        <option value="1">One factor per line, base 2
        <option value="2">One factor per line, base 8
        <option value="3">One factor per line, base 10 (accepts terms)
        <option value="4">One factor per line, base 16
        <option value="5">Multiple factors per line, base 2
        <option value="6">Multiple factors per line, base 8
        <option value="7">Multiple factors per line, base 10
        <option value="8">Multiple factors per line, base 16
        <option value="9">GMP-ECM output
        <option value="10">Msieve output
        <option value="11">Yafu output
        </select></td>
        </tr><tr><td align="center" bgcolor="#DDDDDD"><input type="submit" value="Report"></td>
        </tr></table></center></form>
    """,
}

_factordb_showid = {
    1100000000820004790: b"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
  "http://www.w3.org/TR/html4/loose.dtd">
        <html>
            <head>
                <title>factordb.com</title>
            <script type="text/javascript" src="ajax.js"></script>
            </head>
            <body><table border=0 width="98%"><tr><td width=14% align="center" bgcolor="#BBBBBB"><a href="index.php">Search</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="sequences.php">Sequences</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="result.php">Report results</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="tables.php">Factor tables</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="status.php">Status</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="downloads.php">Downloads</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="login.php">Login</a></td>
        </tr></table><br><form action="index.php" method="GET"><input type="hidden" name="showid" value="1100000000820004790"><table border=0 width="98%"><tr><td align="center" colspan=2 bgcolor="#BBBBBB">Additional information (Internal ID <a href="index.php?id=1100000000820004790">1100000000820004790</a>)</td>
        </tr><tr><td align="center" bgcolor="#DDDDDD">Digits (Base <select name="base" size=1" onchange="submit()"><option value="2">2<option value="3">3<option value="4">4<option value="5">5<option value="6">6<option value="7">7<option value="8">8<option value="9">9<option value="10" selected>10<option value="11">11<option value="12">12<option value="13">13<option value="14">14<option value="15">15<option value="16">16<option value="17">17<option value="18">18<option value="19">19<option value="20">20<option value="21">21<option value="22">22<option value="23">23<option value="24">24<option value="25">25<option value="26">26<option value="27">27<option value="28">28<option value="29">29<option value="30">30<option value="31">31<option value="32">32<option value="33">33<option value="34">34<option value="35">35<option value="36">36</select>)</td>
        <td align="center" bgcolor="#DDDDDD">154</td>
        </tr><tr><td align="center">Number</td>
        <td align="center">211871631508194407115446390648376884488580157654762983495273911633249028872771115077418919885283730478507416949912791691<br>
        8462675640932594243139970187254480<br>
        </td>
        </tr></table></form><br><br>
        <center>
            <font size="-1">
            factordb.com - 8 queries to generate this page (0.01 seconds) (<a href="res.php">limits</a>) (<a href="imp.html">Imprint</a>)
            </font>
        </center>
        </body>
        </html>
    """,
    1100000000820004792: b"""
        <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
          "http://www.w3.org/TR/html4/loose.dtd">
        <html>
            <head>
                <title>factordb.com</title>
            <script type="text/javascript" src="ajax.js"></script>
            </head>
            <body><table border=0 width="98%"><tr><td width=14% align="center" bgcolor="#BBBBBB"><a href="index.php">Search</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="sequences.php">Sequences</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="result.php">Report results</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="tables.php">Factor tables</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="status.php">Status</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="downloads.php">Downloads</a></td>
        <td width=14% align="center" bgcolor="#BBBBBB"><a href="login.php">Login</a></td>
        </tr></table><br><form action="index.php" method="GET"><input type="hidden" name="showid" value="1100000000820004792"><table border=0 width="98%"><tr><td align="center" colspan=2 bgcolor="#BBBBBB">Additional information (Internal ID <a href="index.php?id=1100000000820004792">1100000000820004792</a>)</td>
        </tr><tr><td align="center" bgcolor="#DDDDDD">Digits (Base <select name="base" size=1" onchange="submit()"><option value="2">2<option value="3">3<option value="4">4<option value="5">5<option value="6">6<option value="7">7<option value="8">8<option value="9">9<option value="10" selected>10<option value="11">11<option value="12">12<option value="13">13<option value="14">14<option value="15">15<option value="16">16<option value="17">17<option value="18">18<option value="19">19<option value="20">20<option value="21">21<option value="22">22<option value="23">23<option value="24">24<option value="25">25<option value="26">26<option value="27">27<option value="28">28<option value="29">29<option value="30">30<option value="31">31<option value="32">32<option value="33">33<option value="34">34<option value="35">35<option value="36">36</select>)</td>
        <td align="center" bgcolor="#DDDDDD">147</td>
        </tr><tr><td align="center">Number</td>
        <td align="center">122850342280668807673432007899874804879290282016547868470070085463593989252647008218227958129782893091689947159691338031<br>
        444544438519788235585328939<br>
        </td>
        </tr></table></form><br><br>
        <center>
            <font size="-1">
            factordb.com - 7 queries to generate this page (0.01 seconds) (<a href="res.php">limits</a>) (<a href="imp.html">Imprint</a>)
            </font>
        </center>
        </body>
        </html>
    """,
}


def _static_fetch_factordb_factors(num):
    page_bytes = _factordb_search[num]
    return keydb._parse_factordb_factors(page_bytes)


def _static_fetch_factordb_showid(num):
    page_bytes = _factordb_showid[num]
    return keydb._parse_factordb_showid(page_bytes)


#@ddt.ddt
@patch('teslacrack.keydb.fetch_factordb_factors', _static_fetch_factordb_factors)
@patch('teslacrack.keydb._fetch_factordb_showid', _static_fetch_factordb_showid)
class TFactordb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg on PY2.

    def test_factordb(self):
        factors = keydb.fetch_factordb_factors(_factorized_num)
        self.assertSequenceEqual(factors, _factorized_num_factors)
