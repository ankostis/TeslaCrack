##################
TeslaCrack CHANGES
##################

v0.1.0: XX March 2016: `pip`` distributed cmd-line tool with unified functionality
==================================================================================
To be released in *PyPi*, recfactored as a cmd-line tool.

+ Package tool:
  + Use pypi to distribute tool, installs with: ``pip install teslacrack``
  + Deveopers free to use any library now.
  + Single entry-point console-command ``teslacrack`` with 4 sub-commands:
    ``ls, decrypt, ufactor, key``.

+ Automatically search for primes on "mul" keys in http://factordb.com.
+ Store all discovered key-infos into internal **key-db**; no need to manually
  specify keys, but still possible if needed with ``key`` cmd
+ Search and match keys in **any format** or prefix, quoted or not:
  - *hex*,
  - *num*,
  - *asc* (base64), and
  - *bin* (bytes)

+ ``unfactor.py`` produces a SINGLE candidate AES key, by validating candidates.
+ ``decrypt`` recovers AES-session-key from BTC-private-key.

+ Refactor core functionality:
  + Unify all unfactor-XXX sources into ``unfactor.py``.
  + Add 2 more source-files for key conversion: tesla-file parsing, generation
    of candidate keys &other utilities.
  + Pythonify loops, PY2/P3 meticulously.
  + Proper use of `future` lib (division, builtins, etc).
  + Use `pycoin` lib that is available both in PY2 & PY3.
  + Improve TestCases, also added some for documentation.
  + KeyConversions:
    + Accept keys in ANY format: bytes, hex, integers, b64, as string or bytes, with or without quotes.
    + Header class: Abstract parsing of tesla-files and offsets with a class.

+ docs: FINALLY explain CORRECTLY how TeslaCrypt/Crack works:
  + Officially use the "mul" term for distinguishing it from the public/private ECDH keys

  + List known TeslaCrypt versions and their infos in the README (adapted from TeslaDecoder).
  + Added CHANGES and Versioning.
  + Added GPL-headers to all files.


v0.0.3, 24 Feb 2016, #29: Add TestCases
=======================================
+ TCs:
  + ``teslacrack.py``: just compare stats for different option combinations.
  + ``unfactor.py``: Check reconstruction of known keys.
  + Use ``bash`` for ``chmod`` to imitate inaccessible-files.
  + BREAK the header of "bad-header" tesla-file.

+ ``teslacrack.py``:
  + FIX unbound-var when decrypting alone-files from cmd-line!
  + FIX unicode-handlings in WinPython-2.7.
  + docs: FIX 1st teslacrypt cmd, ``-v`` missplaced-option.
  + minor log also file on unknown keys.
  + Add more known-magics (zip, 7z, png, gifs, etc).
    + Check both extension & magic-bytes before accepting positive.
    + test-files: Set the correct file-exts, needed for ``unfactor.py`` checks.
    + docs: update explanation about magics.

  + Consume AES hex-strings (facilitate TCs).

+ ``unfactorXXX.py``:
  + Put candidates-keys in list, instead of returning them as help-msgs.
    Provide help-message when key not found.
  + Add TCs for (some) error cases.
  + Restruct and logging (facilitate TCs).
  + Output decrypted-AES as hex-string (facilitate TCs).
  + Use logging throughout.

+ All:
  + Raise exceptions instead of returning error-msgs (facilitate TCs).
  + Ensure ``main()``'s exit-error-code non-zero on errors.
  + Standardize ``main()`` arguments and

Note that TCs need these libs::

    pip install ddt, yaml

and ``bash`` for making inaccessible files/dirs for TCs - I (ankostis) suggest
to use [cygwin](https://cygwin.com/install.html) under windows.


v0.0.2, 1 Feb 2016, #19: long-unicode fpaths, don't corrupt if interrupted
==========================================================================
("versioning" did not exist in this version)

Enhance `teslacrack.py` to make it user-friendly, suitable for unlocking (unattended)
1000s of files, without *i18n* issues, and providing activity-report at the end.

+ ``teslacrack.py``:
  + Support unicode long paths with ``\\?\`` win-prefix, accept multiple paths/files from cmd-line.
  + Do not create corrupted or empty decrypted-file when decryption fail.
  + Check expected-size and overwrite corrupted files (NEEDED when interrupted).
  + Support multiple tesla-extensions (e.g., add '.ccc').
  + Use *argparse* lib, substitute ``global`` instances with objects.
  + Simplify traversing recursion with ``os.walk``.
  + Add ``--delete-old``, ``--overwrite`` & ``--fix`` options for dealing with existing locked or unlocked files.
  + Improve logging and ex-reporting (use -v for viewing visited files).
  + Provide stats of what has been done, and print them every N secs with ``--progress``.
  + TESTED also WinPython-2.7 & 3.4, Linux Python2 & 3

+ README:
  + Improve instructions & formatting, state alternative Python version.
  + Give crack-overview and properly explain and name keys in the docs.
    + encrypted-AES-session-key, instead of "public",
    + decrypted (or reconstructed) AES session-key, instead of "private".
    + Clarify decrypted AES-key from locked/unlocked user-files.

  + Add project-coords at the top, make badges work on Github.
  + Separate sections, add table-of-contents.
  + Convert docs from ``.md --> .rst``.


v0.0.1: 25 Feb 2016
===================
("versioning" did not exist in this version)

Googulator's work in a good state.
