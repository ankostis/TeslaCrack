###########################################################
TeslaCrack - decrypt files crypted by TeslaCrypt ransomware
###########################################################
|python-ver| |proj-license| |pypi-ver| |downloads-count| \
|flattr-donate| |btc-donate|

:Release:     0.1.0
:Date:        2016-02-29 11:20:41
:Source:      https://github.com/Googulator/TeslaCrack
:PyPI repo:   https://pypi.python.org/pypi/teslacrack
:Keywords:    TeslaCrypt, ransomware, unlock, cryptography,decryptor, unlocker,
              utility, python,
:Author:      Googulator
:License:     GNU General Public License v3 (GPLv3)

This tool mainly decrypts files from **TeslaCrypt ransomware** < v3.x
(see `TeslaCrypt versions`_, at the bottom).
These versions can be recognized from the extensions ``.vvv, .ccc,  .zzz, .aaa, .abc``
added to the names of you original files, and/or the filenames of the ransom notes
being ``Howto_RESTORE_FILES.txt``.

The tool should may help also ancient versions by reconstructing the *Bitcoin private-key*,
which is utilized by |TeslaDecrypt|_ or |TeslaDecoder|_ external programs.


.. contents:: Table of Contents
  :backlinks: top


Quickstart
==========

- The main entry-point of the tool is the ``teslacrack`` console-command::

    ## Install it.
    > pip install teslacrack

    ## Gather the "mul" key(s) that have encrypted your files:
    > teslacrack decrypt D:\some\infected\folder

    ## Factorize  AES or BTC "mul" keys reported by the command above
    ## or found as factors in http://factordb.com/.
    > msieve -e 0xAD34AD2A32F4EE2...

    ## Guess your AES-session-key from a "known" file-type:
    > teslacrack crack-fkey D:\some\infected\folder\foo.pdf

    ## Edit `Add it into teslacrypt/decrypt.py` file and add
    ##  the key reported above into `known_AES_key_pairs` dict.

    ## Now decrypt all your hard-drive:
    > teslacrack decrypt --progress D:\

  .. Tip::

    To open a ``cmd.exe`` console, press ``[WinKey + R]`` and type ``cmd + [Enter]``
    When issuing commands describe here, skip the ``>`` char or the ``##`` lines.

- More detailed instructions are given in the `How to decrypt your files`_ section.

- More sub-commands are available - to receive their usage description, type::

    > teslacrack --help
    TeslaCrack - decryptor for the TeslaCrypt ransomware.

    Usage:
      teslacrack decrypt  [-v] [--dry-run] [--delete | --delete-old]  [--progress]
                                [(--fix | --overwrite) [--backup=<.ext>]]
                                [<path>]...
      teslacrack crack-fkey     [-v] [--progress] [--ecdh | --btc-addr <btc-addr>]
                                <file>  <prime-factor>...
      teslacrack crack-key      [-v] [--progress] (--ecdh <pub-key> | --btc-addr <btc-addr>)
                                <mul-key>  <prime-factor>...
      teslacrack file           [-v] [ -F <hconv>] <file>  [<field>]...
      teslacrack -h | --help
      teslacrack -V | --version

    Sub-commands:
      decrypt:
          Decrypt tesla-file(s) in <path> file(s)/folder(s) if their AES key
          already guessed, while reporting any unknown AES & BTC mul-key(s) encountered.
          The (rough) pattern of usage is this:
            1. Run this cmd on some tesla-files to gather your mul-AES keys;
            2. factorize the mul-key(s) reported, first by searching http://factordb.com/
               and then use *msieve* or *YAFU* external programs to factorize
               any remaining non-prime ones;
            3. use `crack-XXX` sub-cmds to reconstruct your cleartext keys;
            4. add keys from above into `known_AES_key_pairs`, and then
            5. re-run `decrypt` on all infected file/directories.
          If no <path> given, current-directory assumed.
      crack-fkey:
          Read mul-key(s) from <file> and use the <prime-factor> integers produced by
          external factorization program (i.e. *msieve*) or found in http://factordb.com/
          to reconstruct their key(s), optionally according to *ECDH* or *BTC* methods
          (explained in respective options).
          When no method specified (the default), the <file> must belong to `known_file_magic`.
      crack-key:
          Like the `crack-fkey`, above, but the <mul-key> is explicitly given and
          the method must be one of *ECDH* or *BTC*.  Use the `file` or `decrypt` sub-cmds
          to print the <mul-key>; factorize this to get all <prime-factor>.
      file:
          Print tesla-file's header fields (keys, addresses, etc), or those explicitly
          specified, converted by -F <hconv> option.  Each <field> may be a case-insenstive
          subs-string of fields available.

    Options:
      --ecdh [<pub-key>]     A slower key-reconstructor based on Elliptic-Curve-Cryptography which:
                               - can recover both AES or BTC[1] keys;
                               - can recover keys from any file-type (no need for *magic-bytes*);
                               - yields always a single correct key.
                             For the `crack-fkey` sub-cmd, the <prime-factors> select which key
                             to crack (AES or BTC). For the `crack-key` sub-cmd, specify
                             which <mul-key> and paired <pub-key> to break.
      --btc-addr <btc-addr>  Guess BTC key based on the bitcoin-address and BTC[1] pub-key.
                             The <btc-addr> is typically found in the ransom-note or recovery file
      -F <hconv>             Specify print-out format for tesla-header fields (keys, addresses, etc),
                             where <hconv> is any non-ambiguous case-insensitive *prefix* from:
                               - raw: all bytes as-is - no conversion (i.e. hex mul-keys NOT strip & l-rotate).
                               - fix: like 'raw', but mul-keys fixed and size:int; fail if mul-keys invalid.
                               - bin: all bytes (even mul-keys), mul-keys: fixed.
                               - xhex: all string-HEX, size:bytes-hexed.
                               - hex: all string-hex prefixed with '0x', size: int-hexed.
                               - num: all natural numbers, size: int.
                               - 64: all base64, size(int) - most concise.
                             [default: 64]
      --delete               Delete crypted-files after decrypting them.
      --delete-old           Delete crypted even if decrypted-file created during a previous run
                             [default: False].
      -n, --dry-run          Decrypt but don't Write/Delete files, just report actions performed
                             [default: False].
      --progress             Before start decrypting files, pre-scan all dirs, to
                             provide progress-indicator [default: False].
      --fix                  Re-decrypt tesla-files and overwrite crypted-counterparts if they have
                             unexpected size. If you enable it, by default it backs-up existing files
                             with '.BAK' extension (see `--backup`). Specify empty extension ''
                             for no backups (e.g. `--backup=`)
                             WARNING: You may LOOSE FILES that have changed due to
                             regular use, such as, configuration-files and mailboxes!
                             [default: False].
      --overwrite            Re-decrypt ALL tesla-files, overwritting all crypted-counterparts.
                             Optionally creates backups with the given extension (see `--backup`).
                             WARNING: You may LOOSE FILES that have changed due to
                             regular use, such as, configuration-files and mailboxes!
                             [default: False].
      --backup=<.ext>        Sets file-extension (with dot(`.`) included for backup-files
                             created by `--fix` and `--overwrite` options.
    Other options:
      -h, --help             Show this help message and exit.
      -V, --version          Print program's version number and exit.
      -v, --verbose          Verbosely log(DEBUG) all actions performed.

    Notes:
      [1] Private BTC-key may be used with *TeslaDecoder* external program,
          which should decrypt also ancient versions of TeslaCrypt.
          Check the following for gathering required keys and addresses:
          - http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information
          - https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall

    Examples:

       teslacrack decrypt -v tesla-file.vvv        ## Decrypt file, and if unknwon key, printed.
       teslacrack crack-fkey tesla-file.vvv 1 3 5  ## Unfacrtor the AES-key of the file from primes 1,3,5.
       teslacrack decrypt .  bar\cob.xlsx          ## Decrypt current-folder & a file
       teslacrack decrypt --delete-old C:\\        ## WILL DELETE ALL `.vvv` files on disk!!!
       teslacrack decrypt                          ## Decrypt current-folder, logging verbosely.
       teslacrack decrypt --progress -n -v  C:\\   ## Just to check what actions will perform.

    Enjoy! ;)


Terminology
-----------
Elliptic Cryptography (EC):
    *TeslaCrypt* v2 applies a "amateurish" EC-sheme twice, first on the "Bitcoin" keys,
    and then on the "AES" ones.  During encryption/decryption, for both key-sets, a series of
    different key-types are generated, in the order that are described below.

    There is a nice overview of the `Elliptic Cryptography terms used throughout
    <http://andrea.corbellini.name/2015/05/30/elliptic-curve-cryptography-ecdh-and-ecdsa/>`_
    along with a `simple introduction into the EC "curves"
    <https://blog.cloudflare.com/a-relatively-easy-to-understand-primer-on-elliptic-curve-cryptography/>`_.
    It suffices to know that it is based on a "geometry" defined by "special" multiplications of
    *private-numbers* with x-y *public-points*;  contrary to the Euclidean geometry,
    when given a starting point and the multiplication result, it is infeasible(!)
    to derive the number factor.

EC *Private* Keys:
    These are the keys we try to reconstruct: one *BTC* and one or more *AES* keys.
    In addition to being *EC private numbers*, they have additional functionalities,
    explained below; but above all, they can decrypt directly or inderectly some (or all) files.
    They are not stored anywhere in your computer.

    Bitcoin Private key (other names: ``btc_prv``):
        It is generated during encryption, once per PC, and sent to cyber-criminals.
        It has 2 uses:

        1. It is the "master" EC *EC private number* able to derive all *AES session keys* that have
           encrypted your files.
        2. It makes the *private BTC address*, so if you had sent the money and you recover it before
           the cyber-criminals "spend" them, you may get them back. Read more about BTC calculation
           `here <https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses>`_.

        This is the first key to try to recover.

    AES private key(s) (other names: *AES-session-key*, ``aes_prv``):
        A new such key is randomly generated whenever an infected PC boots.
        Your files are encrypted with this number using `AES symmetric method
        <https://en.wikipedia.org/wiki/Advanced_Encryption_Standard>`_.
        It is "symmetrical" in the sense that the same number also decrypts your files.
        This is you 2nd chance, assuming the *BTC private key* above is too long.


EC *Public* keys (other names: ``btc_pub``, ``aes_pub``):
    There are 2 *EC public point* keys, one for each corresponding *EC private key*, above.
    They are needed during regular decryption to derive the next key-type, the *shared secrets*.
    They are both stored in the header of your encrypted-files.


ECDH Shared *Secrets* (other names: *shared-key*, ``btc_sec``, ``aes_sec``):
    During regular encryption & decryption these 2 keys are temporarily calculated
    according to the *EC Diffie–Hellman* key-exchange protocol: by EC-multiplying
    one *public* key (i.e. BTC) with the opposite *private* one (i.e. AES),
    or vice-versa, since both operations arrive to the same *shared-secret*.
    In the Teslacrypt case, the *private-key* is *SHA256-hashed* first.
    They allow to derive the *AES* key from the *BTC*.
    They are not stored anywhere in your computer.

 *Multiplicative* keys(other names: *"mul"*, ``btc_mul``, ``aes_mul``):
    These 2 keys are the factorization targets; when factorized, the *private-keys*
    are easily derived, since::

      mul := secret * private

    The "weakness" lies in their size (just 128bits)
    They are both stored in the header of your encrypted-files.


How it works?
-------------
We recapitulate `how TeslaCrypt ransomware \< v3.0 works to explain the weakness
<https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall/>`_
that is relevant for this cracking tool:

1. *TeslaCrypt* creates 2 random **AES** and **BTC** private keys - the AES will
   symmetrically[1]_ encrypt your files, the BTC will accept your money - and
   immediately transmits them to the operators of the ransomware (irrelevant here);

2. an "improvised" asymmetrical EC scheme is then used to to encrypt these AES & BTC keys
   within your computer; for redundancy (in case some of the keys are lost during transmission)
   they crypto-criminals employed an additional "big" multiplicative ciphetext (``XXX_mul_key``)
   which unfortunately for them, is not big enough(!).

3. it then starts to encrypt your files one-by-one, attaching these 2 fields
   into the headers of those files.

   Multiple *AES* keys will be generated if you interrupt the ransomware while it encrypts
   your files (i.e. reboot), but only a single *btc* pair is ever created.

*TeslaCrack* implements (primarily) an integer factorization attack against
the ``aes_mul_key`` and ``btc_mul_key`` fields, recovering the original AES-key by just
trying all factor combinations, and using some method for validating that the
tested-key is the correct one (e.g. ECDH schema, BTC address validation).

Additionally it can derive the *AES private key* from the *BTC private key*.

The actual factorization is not implemented within *TeslaCrack* - it only extracts
the numbers to be factored, and you have to feed them into 3rd party factoring tools,
such as `YAFU or msieve
<https://www.google.com/search?q=msieve+factorization>`_.


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


Install TeslaCrack
------------------
1. At a command-prompt with python enabled (and with admin-rights in the "official" distribution),
   do one of the following:

   - Install it directly from the PyPi repository::

        pip install teslacrack

   - Or install it directly the latest version from GitHub::

        pip install git+https://github.com/Googulator/TeslaCrack.git

   - Or install the sources in "develop" mode, assuming you have already
     downloaded them in some folder::

        pip install -e <sources-folder>

   .. Warning::

        If you get an error like ``'pip' is not recognized as an internal or external command ...``
        then you may execute the following Python-2 code and re-run the commands above::

            python -c "import urllib2; print urllib2.urlopen('https://bootstrap.pypa.io/ez_setup.py').read()" | python
            easy_install pip

        If you get native-compilation errors, make sure you have the latest
        your `pip` is upgraded to the latest version::

            python -m pip install -U pip

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

1. Check if this tool can crack you *TeslaCrypt* version:
---------------------------------------------------------
Check that the extension of your crypted files belongs to the known ones (i.e.
``.vvv, .ccc, .zzz, .aaa, .abc``); if your extension is missing, edit
``teslacrack/decrypt.py`` and append it into ``tesla_extensions`` string-list.
For al list of all extensions, read `TeslaCrypt versions`_ at the bottom.

.. Note::

     The extensions ``.ttt, .xxx, .micro`` and ``.mp3``(!) have been
     reported for the new variant of TeslaCrypt >= v3.0, which this tool cannot
     decrypt.


2. Decide which Key to attack:  *BTC* or *AES*?
-----------------------------------------------
You should definetely attempt to factorize your *"mul" BTC* key - but you may be unlucky
and it may be too long. So if you count how many different *"mul"* AES-keys have encrypted
your files, you will know better your road ahead.

.. Tip::

     To understand the various names of keys mentioned in these instructions,
     read the Terminology`_ section.

To gather all "mul" keys, attempt to decrypt your files and check the output
of this command::

    teslacrack decrypt <folder-to-your-crypted-files>

This command should fail to decrypt your files, but will print all unknown
``aes_mul_key`` encountered, as hexadecimal numbers (note that it should report
the same ``btc_mul_key`` for all your files).

If you get a single unknown AES "mul" key, you may also attack it using
the plain ``crack-fkey`` sub-cmd, which is slightly faster. But in any case,
the time-consuming step is no 3, "factorization", not the key-reconstruction.


3. Factorize your "mul" Key:
----------------------------
Factorize the "mul" keys or any composite-factors discovered from `factordb.com
<http://factordb.com/>`_ (those marked as "CF"). If you are lucky, your key may
have been already factorized, and you can skip the next step :-)

- Use one of the *external* factorization programs.
  For instance, using *msieve*::

     msieve -v -e <encrypted-key>

- If your key is in hexadecimal form (as printed by ``decrypt``), prepend it
  with a ``0x`` prefix.

- To convert a key to decimal, e.g. the hex value ``'ae1b015a'``, in Python use
  ``int('ae1b015a', 16)``.
  Alternatively you may view all keys contained in a tesla-file converted as integers
  with this command::

     teslacrack file <your-tesla-file> -Fnum

- The ``-e`` switch is needed to do a "deep" elliptic curve search,
  which speeds up *msieve* for numbers with many factors (by default,
  *msieve* is optimized for semi-primes such as RSA moduli)

- Alternatively, you can use *YAFU*, which is multithreaded, but
  tends to crash often (at least for me)
  If you use *YAFU*, make sure to run it from command line using
  the ``-threads`` option!

- For numbers with few factors (where ``-e`` is ineffective, and *msieve/YAFU*
  run slow), use ``factmsieve.py`` (downloaded optionally above), which is
  more complicated, but also faster, multithreaded, and doesn't tend to crash.

- This step might take considerable time - days is not uncommon.

4. Reconstruct your Key:
------------------------
- Assuming you found a single unknown ``aes_mul_key`` key, you may choose
  the default key-reconstructor which is bit faster - but you must choose a file
  with known magic-bytes in its header:

  - *pdf* & *word-doc* files,
  - images and sounds (*jpg, png, gif, mp3*), and
  - archive formats: *gzip, bz2, 7z, rar* and of course *zip*, which includes
    all LibreOffice and newer Microsoft *docs/xlsx* & *ODF* documents.

  .. Tip::

       To view or extend the supported file-types, edit ``teslacrack/unfactor.py``
       and append a new mapping into ``known_file_magics`` dictionary.
       Note that in *python-3*, bytes are given like that: ``b'\xff\xd8'``.

  Add the primes from previous step, separated by spaces, into this command::

       teslacrack crack-fkey <crypted-file>  <factor-1>  <factor-2> ...

  It will reconstruct and print any decrypted AES-keys candidates (usually just one).

- Alternatively you may use ``--ecdh`` option to break either the AES or the
  BTC key for the |TeslaDecoder|_ tool (see section below).  This option requires
  AES or BTC public keys, which you may get them  also with the ``file`` sub-cmd
  (see previous step on how)::

       teslacrack crack-fkey --ecdh <crypted-file>  <factor-1>  <factor-2> ...

  Which key to break (BTC or AES) gets to be deduced from the factors you provide.

- A 3rd reconstructor is based on *Bitcoin-addresses* and is enacted with the
  ``--btc-addr`` option - read `Break bitcoin-keys for TeslaDecoder`_ section
  below for this.

- As utility, the ``crack-key`` sub-command provides for reconstructing a key
  without the tesla-file that originated from::

      teslacrack crack-key --ecdh <pub-key> <mul-key> <prime-factors>...

  Notice that it requires both types of keys:
  - the ECDH-public AES or BTC key with the ``--ecdh`` option, and
  - the paired "mul" key as its 1st positional argument, before listing the usual
    prime-factors.


5. Register and Test the reconstructed AES key:
-----------------------------------------------
Assuming above you reconstructed your AES key, you may now edit ``teslacrack.py``
and add a new key-pair into the ``known_AES_key_pairs`` dictionary, like that::

    <encrypted-AES-key>: <1st decrypted-AES-key candidate>,

The program accepts hex, integer, base64 or bytes.

To test it, repeat the command from step 2. A decrypted file should now appear
next to the crypted one (``.vvv`` or ``.ccc``, etc) - verify that the contents
of the decrypted-file do make sense.


6. Decrypt all your files:
--------------------------
To decrypt all of your files run from an administrator command prompt::

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


Break bitcoin-keys for *TeslaDecoder*
-------------------------------------

The |TeslaDecoder|_ can decrypt files from all(?) versions, assuming you
have the *bitcoin private-key*.
For very old TeslaCrypt versions (i.e. file-extensions ``ECC, .EXX, or .EZZ``)
*TeslaDecoder* could also extract this BTC private-key.  For later versions, you
have to manually factorize the BTC public-key reported by ``decrypt`` in step 2,
above, and feed its primes into the ``crack-XXX`` sub-cmds with the ``--btc`` option.

This ``crack-key`` sub-cmd requires the *Bitcoin ransom address*,
as reported on the "ransom note", or obtained from:

- For very old v0.x.x TeslaCrypt versions, get it `from the recovery
  '.dat. file <http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information#versions>`_,
  found in the affected machine's ``%AppData%`` folder; the Bitcoin-address is
  the first line.
- For v2 infections, get it `from the registry
  <https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall/#key-data-saved-in-the-system>`_.

.. Note::

   The ``teslacrack decrypt`` can't decode the files encryoted with very old
   TeslaCrypt versions, so you must perform the actual decryption with
   *TeslaDecoder*.

Example:
~~~~~~~~
.. Hint::

    The ``^`` char at the end of each line is the line-continuation characters
    on ``cmd.exe``/DOS.  The respective char in Linux is ```\``.

To reconstruct a BTC priv-key from a tesla-file::

    > teslacrack crack-fkey <tesla-file>  ^
         --btc 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4 ^
         2 2 3 7 11 17 19 139 2311 14278309 465056119273 250220277466967 373463829010805159059 ^
         1261349708817837740609 38505609642285116603442307097561327764453851349351841755789120180499


To reconstruct the same BTC priv-key in 2 steps with the ``crack-key`` sub-cmd
with *base64* formatted pub-key::

    > teslacrack file <tesla-file>  pub-btc -F64
    BEPD/gJGBX0GNtDKu32O6YQ35ubA/jJKI+4aT9jFHbwG2S5t5TFAsFfFGFDhDXLFos4JgYB11BLx2rdynuTWJv4=

    > teslacrack crack-key --btc 1GSswEGHysnASUwNEKNjWXCW9vRCy57qA4 ^
         BEPD/gJGBX0GNtDKu32O6YQ35ubA/jJKI+4aT9jFHbwG2S5t5TFAsFfFGFDhDXLFos4JgYB11BLx2rdynuTWJv4=
         2 2 3 7 11 17 19 139 2311 14278309 465056119273 250220277466967 373463829010805159059 ^
         1261349708817837740609 38505609642285116603442307097561327764453851349351841755789120180499

.. Note::

    Notice that since no file is given, you have to provide the BTC pub-key before the prime-factors.


TeslaCrypt versions
===================
Infos copied and adapted from TeslaDecoder, thanks ;-)

Correspondence of file-extensions to TeslaCrypt/AlphaCrypt versions
-------------------------------------------------------------------
::

    .ecc:               0.2.5 - 0.3.6b
    .ezz:               0.3.7 - 0.3.7b
    .exx:               0.4.0 - 0.4.1a
    .xyz:               1.0.0, 1.0.1
    .zzz:               2.0.0 - 2.0.4a
    .aaa:               2.0.4b - 2.0.5a
    .abc:               2.0.5a, 2.0.5b, 2.1.0, and probably as 2.1.1 test-version,
                        because they went back to version 2.1.0)
    .ccc:               2.1.0a, 2.1.0b, 2.1.0c, 2.1.0d, 2.2.0
    .vvv:               2.2.0
    .xxx|.ttt|.micro:   3.0.0
    .micro|.mp3:        3.0.0a


Version 1:
----------
:File extension:                ``.ecc``
:Data-file on disk:             ``%appdata%\key.dat`` (648 bytes)
:Data in registry:              not used
:Location of log file:          ``%appdata%\log.html``
:Data file protected:           No
:Decryption key offset:         0x177
:Partial key offset:            0x136

If decryption key was zeroed out, but partial key was found in ``key.dat``,
TeslaDecoder can recover original decryption key. This process can take
several hours on slow computers. Encrypted files are not paired with data file.
Decryption key can be also obtained from Tesla's request that was sent to server.


Version 2:
----------
:File extension:                ``.ecc``
:Data-file on disk:             ``%appdata%\key.dat`` (656 bytes
:Data in registry:              not used
:Location of log file:          ``%appdata%\log.html``
:Data file protected:           No
:Decryption key offset:         0x177
:Partial key offset:            0x136

If decryption key was zeroed out, but partial key was found in ``key.dat``,
Tesladecoder can recover original decryption key. This process can take
several hours on slow computers. Encrypted files are not paired with data file.
Decryption key can be also obtained from Tesla's request that was sent to server.


Version 3:
----------
:File extension:                ``.ecc | .ezz``
:Data-file on disk:             ``%appdata%\key.dat`` (752 bytes)
:Data in registry:              ``[HKCU\Software\Microsoft\Windows\CurrentVersion\SET]`` (752 bytes)
:Location of log file:          ``%appdata%\log.html``
:Data file protected:           No
:Decryption key offset:         0x1DB

If decryption key was zeroed out, the decryption key can be recovered
using prime factorization or using private key of TeslaCrypt's authors.
Encrypted files are not paired with data file.
Decryption key can be also obtained from Tesla's request that was sent to server.
Decryption key can be recovered using prime factorization.


Version 4:
----------
:File extension:                ``.ezz | .exx``
:Data-file on disk:             ``%localappdata%\storage.bin`` (752 bytes)
:Data in registry:              ``[HKCU\Software\Microsoft\Windows\CurrentVersion\Settings\storage]`` (752 bytes)
:Location of log file:          ``%localappdata%\log.html``
:Data file protected:           AES 256 can be used
:Decryption key offset:         between 0x19A and 0x2C0

If decryption key was zeroed out, the decryption key can be recovered
using prime factorization or using private key of TeslaCrypt's authors.
Encrypted ``.exx`` files are paired with data file.
Decryption key can be also obtained from Tesla's request that was sent to server.
Decryption key can be recovered using prime factorization.


Version 5/5+:
-------------
:File extension:                ``.xyz | .zzz | .aaa | .abc | .ccc | .vvv``
:Data-file on disk:             not used
:Data in registry:              ``[HKCU\Software\%random%]``
                                (data stored here cannot be used for decryption
                                without Tesla's private key)
:Location of log file:          not used
:Data file protected:           N/A
:Decryption key offset:         N/A

This version doesn't use any data files and decryption key is not
stored on computer. Decryption key can be obtained from Tesla's request that
was sent to server (but not possible since TeslaCrypt v2.1.0).
Decryption key can be recovered using prime factorization.


Version 6: (v2.1.1)
----------
:File extension:                original
:Data-file on disk:             not used
:Data in registry:              not used
:Location of log file:          not used
:Data file protected:           N/A
:Decryption key offset:         N/A

This version doesn't use any data files and decryption key is not stored on computer.
Decryption key can be recovered using prime factorization.


Version 7:
----------
:File extension:                ``.xxx | .ttt | .micro | .mp3``
:Data-file on disk:             not used
:Data in registry:              ``[HKCU\Software\%IDhex%]``
                                (data stored here cannot be used for decryption
                                without Tesla's private key or RandomPrivateKey1)
:Location of log file:          not used
:Data file protected:           N/A
:Decryption key offset:         N/A

This version doesn't use any data files and decryption key is not stored on computer.
There is not any know way to recover decryption key (as of Feb-2016).



And now, for some controversy...
================================

.. image:: https://cloud.githubusercontent.com/assets/16308406/11841119/45709ea2-a3fb-11e5-9df6-8dcc43a6812e.png
.. image:: https://cloud.githubusercontent.com/assets/16308406/11841120/4574e138-a3fb-11e5-981b-5b30e7f8bd84.png

The same day this happened, Kaspersky released this article: https://blog.kaspersky.com/teslacrypt-strikes-again/10860/

|flattr-donate| |btc-donate|

.. |TeslaDecrypt| replace:: *TeslaDecrypt*
.. _TeslaDecrypt: http://www.bleepingcomputer.com/forums/t/574560/ciscos-talos-group-releases-decryptor-for-teslacrypt/

.. |TeslaDecoder| replace:: *TeslaDecoder*
.. _TeslaDecoder: http://www.bleepingcomputer.com/forums/t/576600/tesladecoder-released-to-decrypt-exx-ezz-ecc-files-encrypted-by-teslacrypt/

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
