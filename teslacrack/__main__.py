#! python
# -*- coding: UTF-8 -*-
#
# This is part of TeslaCrack..
#
# Copyright (C) 2016 Googulator
#
# TeslaCrack is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# TeslaCrack is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with TeslaCrack; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
r"""
TeslaCrack - decryptor for the TeslaCrypt ransomware.

Usage:
  teslacrack decrypt  [-v] [--dry-run] [--delete | --delete-old]  [--progress]
                                [(--fix | --overwrite) [--backup=<.ext>]]
                                [<path>]...
  teslacrack guess-fkey     [-v] [--progress] [--ecdsa | --btc <btc-addr>]  <file>  <prime-factor>...
  teslacrack guess-key      [-v] [--progress] (--ecdsa <ecdsa-secret> | --btc <btc-addr>)  <pub-key>  <prime-factor>...
  teslacrack -h | --help
  teslacrack -V | --version

Sub-commands:
  decrypt:
      Decrypt tesla-file(s) in <path> file(s)/folder(s) if their AES private-key
      already guessed, while reporting any unknown AES & BTC public-key(s) encountered.

      The (rough) pattern of usasge is this:
        1. Run this cmd on some tesla-files to gather your public-AES keys,
        2. factorize the public-key(s) reported by *msieve* external program
           or found in http://factordb.com/.
        3. use `guess-XXX` sub-cmds to reconstruct private-keys from public ones,
        4. add public/private key pairs into `known_AES_key_pairs`, and then
        5. re-run `decrypt` on all infected file/directories.

  guess-fkey
      Read public-key(s) from <file> and use the <prime-factor> integers produced by
      external factorization program (i.e. *msieve*) or found in http://factordb.com/
      to reconstruct their private-key(s), optionally according to *ECDSA* or *btc* methods
      (explained in respective options).
      When no method specified (the default), the <file> must belong to `known_file_magic`.

  guess-key
      Like the `guess-fkey`, above, but the <pub-key> is explicitly given and the method
      must be one of *ECDSA* or *btc*.  Use the public-keys reported by `decrypt`.

Options:
  --ecdsa             a slower key-reconstructor based on Elliptic-Curve-Cryptography
                      which:
                      - can recover both AES or BTC private-keys;
                      - can recover keys from any file-type (no need for *magic-bytes*);
                      - yields always a single correct key.
                      Given <prime-factors> select which public-key to use from file (AES or BTC).
                      The private BTC-key may be used with *TeslaDecoder* external program.
  --btc <btc-addr>    Guess BTC private-keys based on the bitcoin-address and BTC public-key.
                      Private BTC-key may be used with *TeslaDecoder* external program,
                      which should decrypt also ancient versions of TeslaCrypt.
                      - The <btc-addr> is typically found in the ransom-note or recovery file
                        ("RECOVERY_KEY.TXT", "recover_file.txt"), dropped in the Documents folder:
                        http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information#versions,
                        or located in the registry:
                        https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall/#key-data-saved-in-the-system
                      - The <pub-key> is the BTC key reported by `decrypt` sub-cmd.
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
Other options:
  -h, --help          Show this help message and exit.
  -V, --version       Print program's version number and exit.
  -v, --verbose       Verbosely log(DEBUG) all actions performed.

Positional arguments:

Examples:

   teslacrack decrypt -v tesla-file.vvv       ## Decrypt file, and if unknwon key, printed.
   teslacrack unfactor tesla-file.vvv 1 3 5   ## Decrypt key of the file from primes 1,3,5.
   teslacrack decrypt .  bar\cob.xlsx         ## Decrypt current-folder & a file
   teslacrack decrypt --delete-old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
   teslacrack decrypt                         ## Decrypt current-folder, logging verbosely.
   teslacrack decrypt --progress -n -v  C:\\  ## Just to check what actions will perform.

Enjoy! ;)
"""

from __future__ import print_function

import logging

import docopt

import teslacrack as tc


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
    v = 'teslacrack-%s' % tc.__version__
    opts = docopt.docopt(__doc__, argv=args or None, version=v)

    _attribufy_opts(opts)
    log_level = logging.DEBUG if opts.verbose else logging.INFO
    tc.init_logging(log_level)
    tc.log.debug('Options: %s', opts)

    try:
        advice_msg = "\n  Re-validate prime-factors."
        key_name = 'AES'
        if opts['decrypt']:
            opts.fpaths = opts['<path>']
            tc.decrypt.decrypt(opts)
        elif opts['guess-fkey']:
            primes = tc.validate_primes(opts['<prime-factor>'])
            file = opts['<file>']

            if opts['--btc']:
                key_name = 'BTC'
                key = tc.unfactor.guess_btc_key_from_btc_address(opts['--btc'], primes)
                if key:
                    return "Found BTC-key: 0x%0.64X" % key
            elif opts['--ecdsa']:
                key_name, key = tc.unfactor.guess_ecdsa_key_from_file(file, primes)
                if key:
                    return "Found %s-key: 0x%0.64X" % (key_name, key)
            else:
                candidate_keys = tc.unfactor.guess_aes_keys_from_file(file, primes)
                if candidate_keys:
                    return "Candidate AES-key(s): \n  %s" % '\n  '.join(
                            '0x%0.64X' % key for key in candidate_keys)
                advice_msg = "\n  Re-validate prime-factors and/or try another file-type."

            raise tc.CrackException("Failed reconstructing %s-key! %s" %
                    (key_name, advice_msg))
        elif opts['guess-key']:
            primes = tc.validate_primes(opts['<prime-factor>'])
            pubkey = opts['<pub-key>']

            if opts['--btc']:
                key_name = 'BTC'
                key = tc.unfactor.guess_btc_key_from_btc_address(
                        opts['--btc'], primes, pubkey)
                if key:
                    return "Found BTC-key: 0x%0.64X" % key
            elif opts['--ecdsa']:
                key = tc.unfactor.guess_ecdsa_key(opts['--ecdsa'], pubkey, primes)
                if key:
                    return "Found ECDSA-key: 0x%0.64X" % key
            else:
                msg = "main() miss-matched *docopt* mutual-exclusive opts (--ecdsa|--btc)! \n  %s"
                raise AssertionError(msg % opts)
            return "Found BTC-key: 0x%0.64X" % key
        else:
            msg = "main() miss-matched *docopt* sub-commands! \n  %s"
            raise AssertionError(msg % opts)
    except tc.CrackException as ex:
        tc.log.error("%r", ex)
        exit(-2)

if __name__ == '__main__':
    print(main())
