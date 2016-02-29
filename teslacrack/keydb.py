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
"""Maitaind keys in textual db, and fetch from http://factordb.com/."""
from __future__ import print_function, unicode_literals, division

from collections import namedtuple
import re

from lxml import html
import requests
from toolz import itertoolz as itz

import itertools as itt
import logging

log = logging.getLogger('teslacrack.keydb')


_factordb_url = 'http://factordb.com'
_extract_factors_xpath='//table//a[font]/@href | //table//a[@href]/font/text()'
_factor_id_regex=re.compile(r'^index.php\?id=(\d+)$')
_factor_num_regex=re.compile(r"""^(?:
        (?P<norm>   \d+ ) |
        (?: (?P<base>\d+) \^ (?P<exp>\d+) ) |
        (?P<dot>    \d+\.\.\.\d+)
)$""", re.VERBOSE)

_extract_showid_xpath='//td[.="Number"]/following-sibling::td[1]/text()'
_extract_showid_regex='\D'

_factor_status = {
    'C': "Composite, no factors known",
    'CF': "Composite, factors known",
    'FF': "Composite, fully factored",
    'P': "Definitely prime",
    'Prp': "Probably prime",
    'U': "Unknown",
    'Unit': "Just for '1'",
    'N': "This number is not in database (and was not added due to your settings)",
    '*': "Added to database during this request",
}

_Factors = namedtuple('_Factors', 'fact status')

def _parse_factordb_showid(page_bytes):
    xptree = html.fromstring(page_bytes)
    fact = xptree.xpath(_extract_showid_xpath)
    log.debug('showid: %s', fact)
    return int(''.join(ff for f in fact for ff in re.split(r'\D+', f) if ff))


def _fetch_factordb_showid(num):
    params = {'showid': int(num), 'raw': None}
    page = requests.get(_factordb_url, params=params)
    log.debug('%s(%s): \n%s', _factordb_url, params, page.text)
    return _parse_factordb_showid(page.content)


def _parse_factordb_factor_pair(href, ftext):
    #print(href, ftext)
    g = _factor_num_regex.match(ftext).groupdict()
    log.debug('fact_groups: %s', g)
    if g['norm']:
        facts =  [int(g['norm'])]
    elif g['base']:
        facts = [int(g['base'])] * int(g['exp'])
    else:
        fid = int(_factor_id_regex.match(href).group(1))
        facts = [_fetch_factordb_showid(fid)]
    return facts

def _parse_factordb_factors(page_bytes):
    xptree = html.fromstring(page_bytes)
    facts_elems = [f for f in xptree.xpath(_extract_factors_xpath)]
    fact_pairs = [_parse_factordb_factor_pair(href, fact)
            for href, fact in itz.partition(2, facts_elems[2:])]

    return list(itt.chain(*fact_pairs))


def fetch_factordb_factors(num):
    params = {'query': int(num), 'raw': None}
    page = requests.get(_factordb_url, params=params)
    log.debug('%s(%s): \n%s', _factordb_url, params, page.text)
    return _parse_factordb_factors(page.content)

