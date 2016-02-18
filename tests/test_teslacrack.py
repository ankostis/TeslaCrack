#! python
# -*- coding: UTF-8 -*-
#
# Copyright 2015 European Commission (JRC);
# Licensed under the EUPL (the 'Licence');
# You may not use this work except in compliance with the Licence.
# You may obtain a copy of the Licence at: http://ec.europa.eu/idabc/eupl
from __future__ import unicode_literals

import os
import teslacrack as tc
import unittest

import ddt


mydir = os.path.dirname(__file__)

_sample_header = tc.Header(
    pub_btc=b'\x04\x17z^\ts\xea4\xff\xae\xba\x8b\xab\xa6\xf8\x8fN\xd1M9CU\x9d{\x16=\xda\xc8\xd4\xdf\xe9\xe5\xa8\x92\xd9(m\xbd\xb5o]\x8e\xd1f\x85\xd5VOb\xfa\xfdD\x1f~\xb4\x0e\xc6*\xf7>\x07s\xd7n\xb1',
    priv_btc=b'372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C\x00\x00',
    pub_aes=b'\x04C\xc3\xfe\x02F\x05}\x066\xd0\xca\xbb}\x8e\xe9\x847\xe6\xe6\xc0\xfe2J#\xee\x1aO\xd8\xc5\x1d\xbc\x06\xd9.m\xe51@\xb0W\xc5\x18P\xe1\rr\xc5\xa2\xce\t\x81\x80u\xd4\x12\xf1\xda\xb7r\x9e\xe4\xd6&\xfe',
    priv_aes=b'9B2A14529F5CEF649FD0330D15B4E59A9F60484DB5D044E44F757521850BC8E1DCDF3CB770FEE0DD2B6A7742B99300ED02103027B742BC862110A1765A8B4FC6\x00\x00',
    iv=b"'Q\n\xbf1\x8di&\x17x\x97+\x98}\xf6\x9f",
    size=7188492
)


@ddt.ddt
class TTeslacrack(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.longMessage = True ## Print also original assertion msg.


    @ddt.data('raw', 'fix', 'bin', 'hex', 'int', 'asc', 'xhex')
    def test_header_conv_smoketest(self, hconv):
        h = tc.hconv(_sample_header, hconv)
        if not any (n.startswith(hconv) for n in ['asc', 'bin', 'hex', 'xhex']):
            self.assertEqual(h.size, _sample_header.size, hconv)
        elif 'hex'.startswith(hconv):
            self.assertEqual(int(h.size, 16), _sample_header.size, hconv)
