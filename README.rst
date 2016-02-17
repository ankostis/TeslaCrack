##########################################################
TeslaCrack - decrypt files crypted by TeslaCrypt ransomware
##########################################################
|python-ver| |proj-license| |pypi-ver| |downloads-count| \
|flattr-donate| |btc-donate|

:Release:     0.2.0
:Date:        2016-02-07 23:51:27
:Source:      https://github.com/Googulator/TeslaCrack
:PyPI repo:   https://pypi.python.org/pypi/teslacrack
:Keywords:    TeslaCrypt, ransomware, unlock, cryptography,decryptor, unlocker,
              utility, python,
:Author:      Googulator
:License:     GNU General Public License v3 (GPLv3)


This is a tool for decrypting files that were crypted with the latest version
(variously known as "v8" or "v2.2.0") of the **TeslaCrypt ransomware**.
This new version can be recognized from the extensions ``.vvv, .ccc,  .zzz, .aaa, .abc``
added to the names of you original files, and/or the filenames of the ransom notes
being ``Howto_RESTORE_FILES.txt``.

The tool should also work against other recent versions of TeslaCrypt -
for ancient versions, use *tesladecrypt* or *TeslaDecoder* together with
the Bitcoin-based key reconstructor instead (``teslacrack unfactorbtc`` subcmd).

.. contents:: Table of Contents
  :backlinks: top

Overview
========
We recapitulate `how TeslaCrypt ransomware works and explain the weakness
<http://www.bleepingcomputer.com/news/security/teslacrypt-decrypted-flaw-in-teslacrypt-allows-victims-to-recover-their-files/>`_
that is relevant for this cracking tool:

1. *TeslaCrypt* creates a symmetrical AES-session-key that will be used to
   encrypt your files,
2. it then asymmetrically ECDH-encrypts that AES-key and transmits the private-ECDH-key
   to the operators of the ransomware (but that is irrelevant here), and finally
3. it starts crypting your files one-by-one, attaching the encrypted-AES-key
   into their header.

- Multiple AES-keys are generated if you interrupt the ransomware while it crypts
  your files (i.e. reboot).

*TeslaCrack* implements (primarily) an integer factorization attack against
the asymmetric scheme (breaking the encrypted-AES-key).
The actual factorization is not implemented within *TeslaCrack*, instead,
it extracts the numbers to be factored, that you have to feed them into
3rd party factoring tools, such as `YAFU or msieve
<https://www.google.com/search?q=msieve+factorization>`_.

Sub-commands
-----------
The main entry-point of the tool is the ``teslacrack`` console-command; open
a ``cmd.exe`` console with ``[WinKey + R], 'cmd' + [Enter]``, and issue the
following to receive its usage description::

    teslacrack --help
    ...

There are 3+1 sub-commands available:

- ``decrypt``: parses the headers from the tesla-files, extracts their
  encrypted AES & BTC keys, and if their corresponding decrypted-AES-key
  has already been reconstructed earlier (by following the steps described below),
  it decrypts those files.

- ``unfactor``: reconstructs an AES-key from the factors of the encrypted-AES-key;
  the factorizations must have happened externally. To check the validity of
  a key reconstructed, it decrypts a file and examines the *magic-bytes* at
  its header - so you have to work with file-types among those registered
  (see `How to decrypt your files`_, below).
  Therefore it may report false positive keys, or fail to find any key at all,
  if the encrypted file selected had been corrupted before picked up by
  the ransomware.

- ``unfactorecdsa``: a slower key-reconstructor with the following advantages
  compared to ``unfactor``:

  - it can recover keys from any file-type (no need for *magic-bytes*),
  - it is guaranteed to always yield a single correct key, and
  - it can also reconstruct Bitcoin private-keys (not just AES ones) that may be
    used with *TeslaDecoder* (see `Break bitcoin-keys for TeslaDecoder`_ section).

- ``unfactorbtc``: A key-reconstructor solely for the BTC-key to be used with
  *TeslaDecoder* tool; it requires the *pybitcoin* py2-only library;
  so if you intend to use it, install with ``pip install teslacrack[btc]`` cmd.



Installation
============

You need a working Python 2.7 or Python-3.4+ environment,
**preferably 64-bit** (if supported by your OS).
A 32-bit Python can also work, but it will be significantly slower

Install Python
--------------
In *Windows*, the following 1 + 2 alternative have been tested:

- The `"official" distributions <https://www.python.org>`_, which **require
  admin-rights to install and to ``pip``-install the necessary packages.**
  Note the official site by default may offer you a 32-bit version -
  choose explicitly the 64-bit version.
  Check also the option for adding Python into your ``PATH``.

- The portable `WinPython <https://winpython.github.io>`_ distributions.
  It has been tested both with: `WinPython-3.4 "slim"
  <http://sourceforge.net/projects/winpython/files/WinPython_3.4/3.4.3.7/>`_
  and `WinPython-2.7 <http://sourceforge.net/projects/winpython/files/WinPython_2.7/2.7.10.3/>`_.
  Notice that by default they do not modify your ``PATH`` so you
  **must run all commands from the included command-prompt executable**.
  And although  they **do not require admin-rights to install**,
  you most probably **need admin-rights** when running ``teslacrack decrypt``,
  if the files to decrypt originate from a different user.

  .. Note::
    The ``unfactorbtc`` & ``unfactorecdsa`` subcommands DO NOT RUN on
    WinPython 3.4 - you have to use 2.7 variant.


Install TeslaCrypt
------------------
1. At a command-prompt with python enabled (and with admin-rights in the "official" distribution),
   do one of the following:

   - Install it directly from the PyPi repository::

        pip install teslacrack

     .. Note::
        If you want to use the alternative *ECDSA* and/or *bitcoin* key-reconstructors
        (see `Sub-commands`_, above), install with this *pip* command::

            pip install teslacrack[btc]

        But notice that the ``btc`` extra library is not(!) available under
        python-3 platforms - you have to failback to python-2 for that.

   - Or install it directly the latest version from GitHub::

        pip install git+https://github.com/Googulator/TeslaCrack.git

   - Or install the sources in "develop" mode, assuming you have already
     downloaded them in some folder::

        pip install -e <sources-folder>

   .. Tip::
        If you get an error like ``'pip' is not recognized as an internal or external command ...``
        then you may execute the following Python-2 code and re-run the commands above::

            python -c "import urllib2; print urllib2.urlopen('https://bootstrap.pypa.io/ez_setup.py').read()" | python
            easy_install pip

        In all cases, check that the command ``teslacrack`` has been installed
        in your path::

            teslacrack --version

2. In addition, you need a program for factoring large numbers.

   For this purpose, I recommend using Msieve (e.g. http://sourceforge.net/projects/msieve/)
   and the ``factmsieve.py`` wrapper.
   Run the factorization on a fast computer, as it can take a lot of processing power.
   On a modern dual-core machine, most encrypted AES-keys can be factorized
   in a few hours, with some unlucky keys possibly taking up to a week.


How to decrypt your files
=========================


1. Check that the extension of your crypted files are one of the known ones,
   ``.vvv, .ccc, .zzz, .aaa, .abc``; if not, edit ``teslacrack/decrypt.py`` to
   append it into ``tesla_extensions`` string-list.

   .. Note::
        The extensions ``.ttt``, ``.xxx``, ``.micro`` and ``.mp3``(!) have been
        reported for the new variant of TeslaCrypt (3.0+), and this tool cannot
        decrypt them, anyway.

2. Count the number of different AES keys that the ransomware has encrypted
   your files with - the answer to this question will tell you which method
   of attack to use against the ransomware.

   To gather all encryption keys used, attempt to decrypt all your files and
   check the output of this command::

       teslacrack decrypt <path-to-your-crypted-files>

   This command will fail to decrypt your files, but it will print out all
   encountered encrypted AES and BTC keys.

3. If the previous step returned a single AES/BTC key-pair only, you may opt for
   attacking directly the AES key, using the plain ``unfactor`` sub-cmd,
   which is usually faster.  In that case you have to choose a file with known
   magic-bytes in its header:

     - *pdf* & *word-doc* files,
     - images and sounds (*jpg, png, gif, mp3*), and
     - archive formats: *gzip, bz2, 7z, rar* and of course *zip*, which includes
       all LibreOffice and newer Microsoft *docs/xlsx* & *ODF* documents.

   .. Tip::
        To view or extend the supported file-types, edit ``teslacrack/unfactor.py``
        and append a new mapping into ``known_file_magics`` dictionary.
        Note that in *python-3*, bytes are given like that: ``b'\xff\xd8'``.


4. Convert your hexadecimal AES or BTC key chosen in the previous step
   to decimal, e.g. in python use ``int('ae1b015a', 16)``, and search
   `factordb.com <http://factordb.com/>`_ for this number. If you are lucky,
   it may have been already factored, and you can skip the next step :-)

5. Factorize the AES or BTC key (this step might take considerable time):

   - Using *msieve*::

         msieve -v -e <encrypted-key>

   - If your key is in hexadecimal form (as printed by ``decrypt``), prepend it
     with a ``0x`` prefix.

   - The ``-e`` switch is needed to do a "deep" elliptic curve search,
     which speeds up *msieve* for numbers with many factors (by default,
     *msieve* is optimized for semiprimes such as RSA moduli)

   - Alternatively, you can use *YAFU*, which is multithreaded, but
     tends to crash often (at least for me)
     If you use *YAFU*, make sure to run it from command line using
     the ``-threads`` option!

   - For numbers with few factors (where ``-e`` is ineffective, and *msieve/YAFU*
     run slow), use ``factmsieve.py`` (downloaded optionally above), which is
     more complicated, but also faster, multithreaded, and doesn't tend to crash.

6. To reconstruct the AES-key that has crypted your files, run::

       teslacrack unfactor <crypteded file>  <primes from previous step, separated by spaces>

   It will reconstruct and print any decrypted AES-keys candidates (usually just one).

   - Alternatively you may use ``unfactorecdsa`` sub-cmd to break either AES or
     BTC key for the *TeslaDecoder* tool (see section below).
     Which key to break gets to be deduced from the factors you provide.
     This sub-cmd has the same syntax as ``unfactor`.  See `Sub-commands`_ for
     an explaination

7. Edit ``teslacrack.py`` to add a new key-pair into the ``known_AES_key_pairs``
   dictionary, like that::

      <encrypted-AES-key>: <1st decrypted-AES-key candidate>,

8. Repeat step 3. A decrypted file should now appear next to the crypted one
   (``.vvv`` or ``.ccc``, etc) - verify that the contents of the decrypted-file
   do make sense.

   - If not, redo step 7, replacing every time a new candidate decrypted AES-key
     in the pair.

9. To decrypt all of your files run from an administrator command prompt::

        teslacrack decrypt --progress D:\\

   - In some cases you may start receiving error-messages, saying
     ``"Unknown key in file: some/file"``.
     This means that some of your files have been crypted with different
     AES-keys (i.e. the ransomware had been restarted due to a reboot).
     ``teslacrack decrypt`` will print at the end any new encrypted AES-key(s)
     encountered - repeat the procedure from step 4 for all newly discovered
     key(s) :-(

   - ``decrypt`` sub-command accepts an optional ``--delete`` and ``--delete-old``
     parameters, which will delete the crypted-files of any cleartext file it
     successfully generates (or already has generated, for the 2nd option).
     Before using this option, make sure that your files have been indeed
     decrypted correctly!

   - By skipping this time the ``-v`` option (verbose logging) you avoid listing
     every file being visited - only failures and totals are reported.

   - Use ``--overwrite`` or the more "selective" ``--fix`` option to
     re-generate all cleartext files or just those that had previously failed to
     decrypt, respectively.  They both accept an optional *file-extension*
     to construct the backup filename.
     Note that by default ``--overwrite`` does not make backups, while the
     ``-fix`` option, does.

   - If you are going to decrypt 1000s of file (i.e ``D:\\``), it's worth
     using the ``--precount`` option; it will consume some initial time to
     pre-calculate directories to be visited, and then a progress-indicator
     will be printed while decrypting.

   - Finally, You can "dry-run" all of the above (decrypting, deletion and backup)
     with the ``-n`` option.

   - Read decriptions for available options with::

        teslacrack --help

Break bitcoin-keys for *TeslaDecoder*
-------------------------------------

The `TeslaDecoder <https://www.google.com/search?q=TeslaDecoder>`_ can decrypt
files from all(?) versions, assuming you have the *private bitcoin key*.
For very old TeslaCrypt versions (i.e. file-extensions ``ECC, .EXX, or .EZZ``)
*TeslaDecoder* could also extract this private-btc-key.  For later versions, you
have to manually factorize the BTC-key reported by ``decrypt`` in step 2, above,
and feed its primes into the ``unfactorbtc`` or ``unfactorecdsa`` sub-cmds.

This first sub-cmd, ``unfactorbtc`` requires the *Bitcoin ransom address*,
as reported on the "ransom note", or obtained from:

- For very old v0.x.x TeslaCrypt versions, get it `from the recovery
 '.dat. file <http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information#versions>`_,
  found in the affected machine's ``%AppData%`` folder; the Bitcoin-address is
  the first line.
- For v2 infections, get it `from the registry
  <https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall/#key-data-saved-in-the-system>`_.

The ``unfactorbtc`` syntax is like ``unfactor`` sub-cmd, but wth the
*btc-address* in place of the filename.

.. Note::
   The ``teslacrack decrypt`` can't decode the files encryoted withvery old
   TeslaCrypt versions, so you must perform the actual decryption with
   *TeslaDecoder*.

.. Tip:
   If you receive an ``ImportError``, make sure that you've installed any
   *extras* required for the key-reconstructor you choose to work with
   (see `Install TeslaCrypt`_, above).


And now, for some controversy...
================================

.. image:: https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png
.. image:: https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/

|flattr-donate| |btc-donate|


.. |python-ver| image:: https://img.shields.io/badge/python-py27%2Cpy34%2B-blue.svg
    :alt: Supported Python versions
.. |proj-license| image:: https://img.shields.io/badge/license-GPLv3-blue.svg
    :target: https://raw.githubusercontent.com/Googulator/teslacrack/master/LICENSE.txt
    :alt: Project License
.. |pypi-ver| image::  https://img.shields.io/pypi/v/teslacrack.svg
    :target: https://pypi.python.org/pypi/teslacrack/
    :alt: Latest Version in PyPI
.. |downloads-count| image:: https://img.shields.io/pypi/dm/teslacrack.svg?period=week
    :target: https://pypi.python.org/pypi/teslacrack/
    :alt: Downloads
.. |flattr-donate| image:: https://img.shields.io/badge/flattr-donate-yellow.svg
    :alt: Donate to this project using Flattr
    :target: https://flattr.com/profile/Googulator
    :class: badge-flattr
.. |btc-donate| image:: https://img.shields.io/badge/bitcoin-donate-yellow.svg
    :alt: Donate once-off to this project using Bitcoin
    :target: bitcoin:1AdcYneBgky3yMP7d2snQ5wznbWKzULezj
    :class: badge-bitcoin
