# This is part of TeslaCrack - decrypt files encrypted by TeslaCrypt ransomware.
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
"""
TeslaCrack - decryptor for the TeslaCrypt ransomware.

Usage:
  teslacrack decrypt  [-v] [--dry-run] [--delete | --delete-old] [--progress]
                                [(--fix | --overwrite) [--backup=<.ext>]]
                                [<path>]...
  teslacrack unfactor      [-v] <file-path> <prime-factor>...
  teslacrack unfactorbtc   [-v] <btc-key> <prime-factor>...
  teslacrack unfactorecdsa [-v] <file-path> <prime-factor>...
  teslacrack -h | --help
  teslacrack -V | --version

Options:
  --delete            Delete crypted-files after decrypting them.
  --delete-old        Delete crypted even if decrypted-file created during a
                      previous run [default: False].
  -n, --dry-run       Decrypt but don't Write/Delete files, just report
                      actions performed [default: False].
  --progress          Before start decrypting files, pre-scan all dirs, to
                      provide progress-indicator [default: False].
  --fix               Re-decrypt tesla-files and overwrite crypted-
                      counterparts if they have unexpected size. If ou enable it,
                      by default it backs-up existing files with '.BAK' extension
                      (see `--backup`). Specify empty extension '' for no backups
                      (e.g. `--backup=`)
                      WARNING: You may LOOSE FILES that have changed due to
                      regular use, such as, configuration-files and mailboxes!
                      [default: False].
  --overwrite         Re-decrypt ALL tesla-files, overwritting all crypted-
                      counterparts. Optionally creates backups with the
                      given extension (see `--backup`).
                      WARNING: You may LOOSE FILES that have changed due to
                      regular use, such as, configuration-files and mailboxes!
                      [default: False].
  --backup=<.ext>     Sets file-extension (with dot(`.`) included for backup-files
                      created by `--fix` and `--overwrite` options.
  -v, --verbose       Verbosely log(DEBUG) all actions performed.
Other:
  -h, --help          Show this help message and exit.
  -V, --version       Print program's version number and exit.

Positional arguments:
  <path>              File or folder with crypted files to act upon.
  <file-path>         Crypted filepath to act upon.
  <btc-key>           The bitcoin-key as reported by `decrypt` sub-cmd.
  <prime-factor>      An integer produced by factorization program or found
                      in http://factordb.com/

Sub-commands:
  decrypt             Scan all <file-path> provided for tesla-files to decrypt,
                      if their AES-key have been factorized, or report any unknown
                      encrypted-AES-key(s).
  unfactor            Read encrypted-AES-key from <file-path> and decrypted
                      based on the provided <prime-factor> integers.
  unfactorbtc         Like the previous sub-cmd, but works with bitcoin addresses.
  unfactorecdsa       Read encrypted-AES-key from <file-path> and decrypted
                      based on the provided <prime-factor> integers.

Examples:

   teslacrack decrypt -v tesla-file.vvv       ## Decrypt file, and if unknwon key, printed.
   teslacrack unfactor tesla-file.vvv 1 3 5   ## Decrypt key of the file from primes 1,3,5.
   teslacrack decrypt .  bar\cob.xlsx         ## Decrypt current-folder & a file
   teslacrack decrypt --delete-old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
   teslacrack decrypt                         ## Decrypt current-folder, logging verbosely.
   teslacrack decrypt --progress -n -v  C:\\  ## Just to check what actions will perform.

Notes:
  To use, factor the 2nd hex string found in the headers of affected files using msieve.
  The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
  Insert the hex string & AES key below, under known_AES_key_pairs, then run on affected directory.
  If an unknown key is reported, crack that one using msieve, then add to known_AES_key_pairs and re-run.

Enjoy! ;)
"""
import logging
import sys
from teslacrack import CrackException

import docopt

from teslacrack import (__version__, init_logging, log,
               decrypt, unfactor, unfactor_bitcoin, unfactor_ecdsa)

def _attribufy_opts(opts):
    """
    Attach opts-items as attributes, with dashes L-trimmed, and args normalized.

    OF course they must not class.
    """
    for k, v in opts.items():
        if k.startswith('-'):
            setattr(opts, k.lstrip('-'), v)
        elif k.startswith('<'):
            setattr(opts, k[1:-1].replace('-', '_'), v)


def main(*args):
    opts = docopt.docopt(__doc__, argv=args or None, version=__version__)

    _attribufy_opts(opts)
    log_level = logging.DEBUG if opts.verbose else logging.INFO
    log.debug('Options: %s', opts)
    init_logging(log_level)

    if opts['decrypt']:
        opts.fpaths = opts['<path>']
        decrypt.decrypt(opts)
    elif opts['unfactor']:
        primes = [int(p) for p in opts['<prime-factor>']]
        try:
            candidate_keys = unfactor.unfactor_key_from_file(
                    opts['<file-path>'], primes)
            print("Candidate decrypted AES key(s): \n  %s" % '\n  '.join(candidate_keys))
        except CrackException as ex:
            log.error("Reconstruction failed! %s", ex)
    elif opts['unfactorbtc']:
        candidate_keys = unfactor_bitcoin.main(opts['<btc-key>'],
                opts['<prime-factor>'])
    elif opts['unfactorecdsa']:
        candidate_keys = unfactor_ecdsa.main(opts['<file-path>'],
                opts['<prime-factor>'])
    else:
        msg = 'Program-logic miss-matches *docopt* sub-commands! \n  %s'
        raise AssertionError(msg % opts)

if __name__ == '__main__':
    main()
