#! python
#-*- coding: utf-8 -*-
''''
Installation script for *TeslaCrack*.


Install:
========

- To install it in "develop" mode, assuming you have download the sources,
  you may type::

      pip install -e <sources-folder>

- Or get it directly from the PyPi repository::

      pip install teslacrack

- Or get it directly from the github repository::

      pip install git+https://github.com/Googulator/TeslaCrack.git
  '''
import io
import os
import sys

from setuptools import setup, find_packages


# Fail early on ancient python-versions
#
py_ver = sys.version_info
if py_ver < (2, 7) or py_ver >= (3,) and py_ver < (3, 3):
    exit("Sorry, Python-2.7+ or Python-3.3+ is supported! Not %s" % py_ver)

mydir = os.path.dirname(__file__)


# Version-trick to have version-info in a single place,
# taken from: http://stackoverflow.com/questions/2058802/how-can-i-get-the-version-defined-in-setup-py-setuptools-in-my-package
##
def read_project_version():
    fglobals = {}
    with io.open(os.path.join(
            mydir, 'teslacrack', '__init__.py'), encoding='UTF-8') as fd:
        exec(fd.read(), fglobals)  # To read __version__
    return fglobals['__version__']


def read_text_lines(fname):
    with io.open(os.path.join(mydir, fname)) as fd:
        return fd.readlines()

proj_ver = read_project_version()
readme_lines = read_text_lines('README.rst')
description = readme_lines[1]
long_desc = ''.join(readme_lines)

setup(
    name='teslacrack',
    version=proj_ver,
    description=description,
    long_description=long_desc,
    author="Googulator",
    #author_email="???@XXX",
    url="https://github.com/Googulator/TeslaCrack",
    download_url='https://github.com/Googulator/TeslaCrack/v%s' % proj_ver,
    keywords=[
        'TeslaCrypt', "ransomware", "unlock", "cryptography",
        "decryptor", "unlocker", "utility", "python",
    ],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: Implementation :: CPython",
        "Development Status :: 3 - Alpha",
        'Natural Language :: English',
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        'Environment :: Console',
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Recovery Tools",
        "Topic :: Utilities",
    ],
    packages=find_packages(exclude=["tests"]),
    install_requires=['pycryptodome', 'ecdsa', 'pybitcoin'],
    tests_require=['ddt'],
    #entry_points={'console_scripts': ['teslacrack = teslacrack.__main__:main']},
    zip_safe=True,
    options={'bdist_wheel': {'universal': True}},
    platforms=['any'],
)
