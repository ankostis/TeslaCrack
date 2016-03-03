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
from __future__ import print_function, unicode_literals, division

import logging
import re

from future import utils as futils
from future.builtins import str, int, bytes
from future.standard_library import install_aliases

from ._version import __version__, __updated__


__title__ = "teslacrack"
__summary__ = "Decrypt files crypted by TeslaCrypt ransomware"
__uri__ = "https://github.com/Googulator/TeslaCrack"
__license__ = 'GNU General Public License v3 (GPLv3)'


class CrackException(Exception):
    pass


log = logging.getLogger('teslacrack')

#: Controls the ``repr()`` of :class:`Header` and :class:`PairedKeys` instances.
repr_conv = 'hex'
install_aliases()
