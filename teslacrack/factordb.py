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
"""Fetch factors from http://factordb.com/."""
from __future__ import print_function, unicode_literals, division

import logging
import re

from lxml import html
import requests
from toolz import itertoolz as itz

from . import CrackException


log = logging.getLogger(__name__)


_url = 'http://factordb.com'
_extract_factors_xpath='//table//a[font]/@href | //table//a[@href]/font/text()'
_factor_id_regex=re.compile(r'^index.php\?id=(\d+)$')
_factor_num_regex=re.compile(r"""^(?:
        (?P<norm>   \d+ ) |
        (?: (?P<base>\d+) \^ (?P<multi>\d+) ) |
        (?P<dot>    \d+\.\.\.\d+)
)$""", re.VERBOSE)

_extract_status_xpath='//td[starts-with(., "status")]/../following-sibling::tr/td[1]/text()'

_extract_showid_xpath='//td[.="Number"]/following-sibling::td[1]/text()'
_extract_showid_regex='\D'

_factor_statuses = {
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


def _xpath(xtree, *args, **kwds):
    if 'smart_strings' not in kwds:
        kwds['smart_strings'] = False
    return xtree.xpath(*args, **kwds)

def _parse_showid(page_bytes):
    xtree = html.fromstring(page_bytes)
    fact = _xpath(xtree,_extract_showid_xpath)
    log.debug('showid: %s', fact)
    return int(''.join(ff for f in fact for ff in re.split(r'\D+', f) if ff))


def _fetch_num_by_id(num):
    params = {'showid': int(num), 'raw': None}
    page = requests.get(_url, params=params)
    log.debug('%s(%s): \n%s', _url, params, page.text)
    return _parse_showid(page.content)


def _parse_factor_pair(href, ftext, primes, composites):
    #print(href, ftext)
    fid = int(_factor_id_regex.match(href).group(1))
    multi = 1
    g = _factor_num_regex.match(ftext).groupdict()
    log.debug('fact_groups: %s', g)
    if g['norm']:
        f = int(g['norm'])
    elif g['base']:
        f = int(g['base'])
        multi = int(g['multi'])
    else:
        f = _fetch_num_by_id(fid)

    ## Check http://factordb.com/status.php:
    #    Smallest composite without known factors (as 29-feb 92 digits)
    if len(str(f)) < 92:
        primes.extend([f] * multi)
    else:
        fetch_factors(f, primes, composites)


def _parse_factors(page_bytes, primes, composites, num):
    xtree = html.fromstring(page_bytes)
    status = _xpath(xtree,_extract_status_xpath)
    status = status[0]
    assert status in _factor_statuses, status

    facts_elems = [f for f in _xpath(xtree,_extract_factors_xpath)]
    nfacts_x_2 = len(facts_elems)
    assert nfacts_x_2 % 2 == 0, facts_elems

    ## 1st pair is always `num`.
    if nfacts_x_2 == 4:
        if status == 'P':
            primes.append(num)
        else:
            composites.append((num, "(%s) %s" % (status, _factor_statuses[status])))
    else:
        for href, fact in itz.partition(2, facts_elems[2:]):
            _parse_factor_pair(href, fact, primes, composites)


def fetch_factors(num, primes=None, composites=None):
    """
    :param list primes:
            to be filled, if provided
    :param list composites:
            to be filled, if provided
    """
    if primes is None:
        primes = []
    if composites is None:
        composites = []
    params = {'query': int(num), 'raw': None}
    page = requests.get(_url, params=params)
    log.debug('%s(%s): \n%s', _url, params, page.text)
    try:
        _parse_factors(page.content, primes, composites, num)
        return primes, composites
    except AssertionError as ex:
        raise CrackException("Searching(%s) in '%s' failed due to: %r" %
                (num, _url, ex))

