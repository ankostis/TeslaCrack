##########################################################
TeslaCrack - decrypt files crypted by TeslaCrypt ransomware
##########################################################
|python-ver| |proj-license| |pypi-ver| |downloads-count| \
|flattr-donate| |btc-donate|

:Release:     0.3.0
:Date:        2016-02-18 04:15:11
:Source:      https://github.com/Googulator/TeslaCrack
:PyPI repo:   https://pypi.python.org/pypi/teslacrack
:Keywords:    TeslaCrypt, ransomware, unlock, cryptography,decryptor, unlocker,
              utility, python,
:Author:      Googulator
:License:     GNU General Public License v3 (GPLv3)


This is a tool for decrypting files that were encrypted with the versions < 3.0
of the **TeslaCrypt ransomware** (variously known as "v8" or "v2.2.0").

These versions can be recognized from the extensions ``.vvv, .ccc,  .zzz, .aaa, .abc``
added to the names of you original files, and/or the filenames of the ransom notes
being ``Howto_RESTORE_FILES.txt``.
The tool should may help also ancient versions by reconstructing the Bitcoin private-key,
which is utilized by *tesladecrypt* or *TeslaDecoder* external programs

*TeslaCrack* implements (primarily) an integer factorization attack against
the asymmetric scheme (breaking the encrypted-AES-key).
The actual factorization is not implemented within *TeslaCrack*, instead,
it just extracts the numbers to be factored, and you have to feed them into
3rd party factoring tools, such as `YAFU or msieve
<https://www.google.com/search?q=msieve+factorization>`_.


.. contents:: Table of Contents
  :backlinks: top

Quickstart
----------

The main entry-point of the tool is the ``teslacrack`` console-command::

    ## Gather the public-AES keys that have encrypted your files:
    > teslacrack decrypt D:\some\infected\folder

    ## Factorize public-AES keys reported by the command above
    ## or found as factors in http://factordb.com/.
    > msieve -e 0xAD34AD2A32F4EE2...

    ## Guess your decrypted-AES key from a "known" file-type:
    > teslacrack guess-fkey D:\some\infected\folder\foo.pdf

    ## Now decrypt all your hard-drive:
    > teslacrack decrypt --progress D:\

.. Tip::
    To open a ``cmd.exe`` console, press ``[WinKey + R]`` and type ``cmd + [Enter]``
    When issuing commands describe here, skip the ``>`` char or the ``##`` lines


There are more sub-commands available - to receive usage description, type::

    > teslacrack --help
    TeslaCrack - decryptor for the TeslaCrypt ransomware.

    Usage:
      teslacrack decrypt  [-v] [--dry-run] [--delete | --delete-old]  [--progress]
                                    [(--fix | --overwrite) [--backup=<.ext>]]
                                    [<path>]...
      teslacrack guess-fkey     [-v] [--progress] [--ecdsa | --btc <btc-addr>]  <file>  <prime-factor>...
      teslacrack guess-key      [-v] [--progress] (--ecdsa <ecdsa-secret> | --btc <btc-addr>)  <pub-key>  <prime-factor>...
      teslacrack file           [-v] [ -I <hconv>] <file>
      teslacrack -h | --help
      teslacrack -V | --version

    Sub-commands:
      decrypt:
          Decrypt tesla-file(s) in <path> file(s)/folder(s) if their AES private-key
          already guessed, while reporting any unknown AES & BTC public-key(s) encountered.

          The (rough) pattern of usage is this:
            1. Run this cmd on some tesla-files to gather your public-AES keys,
            2. factorize the public-key(s) reported by *msieve* external program
               or found in http://factordb.com/.
            3. use `guess-XXX` sub-cmds to reconstruct private-keys from public ones,
            4. add public/private key pairs into `known_AES_key_pairs`, and then
            5. re-run `decrypt` on all infected file/directories.
          If no <path> given, current-directory assumed.

      guess-fkey:
          Read public-key(s) from <file> and use the <prime-factor> integers produced by
          external factorization program (i.e. *msieve*) or found in http://factordb.com/
          to reconstruct their private-key(s), optionally according to *ECDSA* or *btc* methods
          (explained in respective options).
          When no method specified (the default), the <file> must belong to `known_file_magic`.

      guess-key
          Like the `guess-fkey`, above, but the <pub-key> is explicitly given and the method
          must be one of *ECDSA* or *btc*.  Use the public-keys reported by `decrypt`.

      file:
          Print tesla-file's header fields (keys, addresses, etc), converted by -I <hconv> option.

    Options:
      --ecdsa           A slower key-reconstructor based on Elliptic-Curve-Cryptography which:
                          - can recover both AES or BTC[1] private-keys;
                          - can recover keys from any file-type (no need for *magic-bytes*);
                          - yields always a single correct key.
                        The <prime-factors> select which public-key to use from file (AES or BTC).
      --btc <btc-addr>  Guess BTC private-keys based on the bitcoin-address and BTC public-key.
                          - The <btc-addr> is typically found in the ransom-note or recovery file
                          - The <pub-key> is the BTC key reported by `decrypt` sub-cmd.
      -I <hconv>        Specify print-out format for tesla-header fields (keys, addresses, etc),
                        where <hconv> is any non-ambiguous case-insensitive *prefix* from:

                          - raw: all bytes as-is - no conversion (i.e. hex private-keys NOT strip & l-rotate).
                          - fix: like 'raw', but priv-keys fixed and size:int.
                          - bin: all bytes (even private-keys), priv-keys: fixed.
                          - xhex: all string-hex, size:bytes-hexed.
                          - hex: all string-hex prefixed with '0x', size: int-hexed.
                          - num: all natural numbers, size: int.
                          - asc: all base64, size(int) - most concise.
                        [default: fix]
      --delete          Delete crypted-files after decrypting them.
      --delete-old      Delete crypted even if decrypted-file created during a
                        previous run [default: False].
      -n, --dry-run     Decrypt but don't Write/Delete files, just report
                        actions performed [default: False].
      --progress        Before start decrypting files, pre-scan all dirs, to
                        provide progress-indicator [default: False].
      --fix             Re-decrypt tesla-files and overwrite crypted-
                        counterparts if they have unexpected size. If ou enable it,
                        by default it backs-up existing files with '.BAK' extension
                        (see `--backup`). Specify empty extension '' for no backups
                        (e.g. `--backup=`)
                        WARNING: You may LOOSE FILES that have changed due to
                        regular use, such as, configuration-files and mailboxes!
                        [default: False].
      --overwrite       Re-decrypt ALL tesla-files, overwritting all crypted-
                        counterparts. Optionally creates backups with the
                        given extension (see `--backup`).
                        WARNING: You may LOOSE FILES that have changed due to
                        regular use, such as, configuration-files and mailboxes!
                        [default: False].
      --backup=<.ext>   Sets file-extension (with dot(`.`) included for backup-files
                        created by `--fix` and `--overwrite` options.
    Other options:
      -h, --help        Show this help message and exit.
      -V, --version     Print program's version number and exit.
      -v, --verbose     Verbosely log(DEBUG) all actions performed.

    Notes:
      [1] Private BTC-key may be used with *TeslaDecoder* external program,
          which should decrypt also ancient versions of TeslaCrypt.
          Check the following for gathering required keys and addresses:
          - http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information
          - https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall

    Examples:

       teslacrack decrypt -v tesla-file.vvv       ## Decrypt file, and if unknwon key, printed.
       teslacrack unfactor tesla-file.vvv 1 3 5   ## Decrypt key of the file from primes 1,3,5.
       teslacrack decrypt .  bar\cob.xlsx         ## Decrypt current-folder & a file
       teslacrack decrypt --delete-old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
       teslacrack decrypt                         ## Decrypt current-folder, logging verbosely.
       teslacrack decrypt --progress -n -v  C:\\  ## Just to check what actions will perform.

    Enjoy! ;)

Step-by-step instructions are given in the `How to decrypt your files`_ section.



Installation
============

You need a working Python 2.7 or Python-3.4+ environment,
**preferably 64-bit** (if supported by your OS).
A 32-bit Python can also work, but it will be significantly slower

  .. Note::
    The ``--btc`` option DOES NOT RUN on Python 3 - use a Python-2.7.

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


Install TeslaCrypt
------------------
1. At a command-prompt with python enabled (and with admin-rights in the "official" distribution),
   do one of the following:

   - Install it directly from the PyPi repository::

        pip install teslacrack

     .. Note::
        If you want to use the alternative *ECDSA* and/or *bitcoin* key-reconstructors
        (see `Quickstart`_, above), install with this *pip* command::

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
     This sub-cmd has the same syntax as ``unfactor`.  See `Quickstart`_ for
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

        teslacrack decrypt --progress D:\

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

   - If you are going to decrypt 1000s of file (i.e ``D:\``), it's worth
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
files from all(?) versions, assuming you have the *bitcoin private-key*.
For very old TeslaCrypt versions (i.e. file-extensions ``ECC, .EXX, or .EZZ``)
*TeslaDecoder* could also extract this BTC private-key.  For later versions, you
have to manually factorize the BTC public-key reported by ``decrypt`` in step 2,
above, and feed its primes into the ``guess-XXX`` sub-cmds with the ``-btc`` option.

This ``guess-key`` sub-cmd requires the *Bitcoin ransom address*,
as reported on the "ransom note", or obtained from:

- For very old v0.x.x TeslaCrypt versions, get it `from the recovery
 '.dat. file <http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information#versions>`_,
  found in the affected machine's ``%AppData%`` folder; the Bitcoin-address is
  the first line.
- For v2 infections, get it `from the registry
  <https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall/#key-data-saved-in-the-system>`_.

.. Note::
   The ``teslacrack decrypt`` can't decode the files encryoted withvery old
   TeslaCrypt versions, so you must perform the actual decryption with
   *TeslaDecoder*.

Example:
~~~~~~~~
.. Hint::
    The ``^`` char at the end of each line is the line-continuation characters
    on ``cmd.exe``/DOS.  The respective char in Linux is ```\``.

::

    > teslacrack guess-f --btc 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4 ^
         372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C ^
         2 2 3 7 11 17 19 139 2311 14278309 465056119273 250220277466967 373463829010805159059 ^
         1261349708817837740609 38505609642285116603442307097561327764453851349351841755789120180499

    > teslacrack guess-f --btc 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4 ^
         372AE820BBF2C3475E18F165F46772087EFFC7D378A3A4D10789AE7633EC09C74578993A2A7104EBA577D229F935AF77C647F18E113647C25EF19CC7E4EE3C4C ^
         2 2 3 7 11 17 19 139 2311 14278309 465056119273 250220277466967 373463829010805159059 ^
         1261349708817837740609 38505609642285116603442307097561327764453851349351841755789120180499


.. Tip:
   If you receive an ``ImportError``, make sure that you've installed any
   *extras* required for the key-reconstructor you choose to work with
   (see `Install TeslaCrypt`_, above).


How it works?
=============
We recapitulate `how TeslaCrypt ransomware works and explain the weakness
<http://www.bleepingcomputer.com/news/security/teslacrypt-decrypted-flaw-in-teslacrypt-allows-victims-to-recover-their-files/>`_
that is relevant for this cracking tool:

1. *TeslaCrypt* creates a symmetrical AES-session-key that will be used to
   encrypt your files,
2. it then asymmetrically ECDH-encrypts that AES-key and transmits the private-ECDH-key
   to the operators of the ransomware (but that is irrelevant here), and finally
3. it starts encrypting your files one-by-one, attaching the encrypted-AES-key
   into their header.

- Multiple AES-keys are generated if you interrupt the ransomware while it encrypts
  your files (i.e. reboot).


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
