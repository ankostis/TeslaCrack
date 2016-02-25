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
  teslacrack crack-fkey     [-v] [--progress] [--ecdsa | --btc <btc-addr>]  <file>  <prime-factor>...
  teslacrack crack-key      [-v] [--progress] (--ecdsa <ecdsa-secret> | --btc <btc-addr>)  <pub-key>  <prime-factor>...
  teslacrack file           [-v] [ -F <hconv>] <file>  [<field>]...
  teslacrack -h | --help
  teslacrack -V | --version

Sub-commands:
  decrypt:
      Decrypt tesla-file(s) in <path> file(s)/folder(s) if their AES private-key
      already guessed, while reporting any unknown AES & BTC public-key(s) encountered.

      The (rough) pattern of usage is this:
        1. Run this cmd on some tesla-files to gather your public-AES keys;
        2. factorize the public-key(s) reported, first by searching http://factordb.com/
           and then use *msieve* or *YAFU* external programs to factorize
           any remaining non-prime ones;
        3. use `crack-XXX` sub-cmds to reconstruct private-keys from public ones;
        4. add public/private key pairs into `known_AES_key_pairs`, and then
        5. re-run `decrypt` on all infected file/directories.

      If no <path> given, current-directory assumed.

  crack-fkey:
      Read public-key(s) from <file> and use the <prime-factor> integers produced by
      external factorization program (i.e. *msieve*) or found in http://factordb.com/
      to reconstruct their private-key(s), optionally according to *ECDSA* or *btc* methods
      (explained in respective options).
      When no method specified (the default), the <file> must belong to `known_file_magic`.

  crack-key
      Like the `crack-fkey`, above, but the <pub-key> is explicitly given and the method
      must be one of *ECDSA* or *btc*.  Use the public-keys reported by `file` or
      `decrypt` suc-cmds.

  file:
      Print tesla-file's header fields (keys, addresses, etc), or those explicitly
      specified, converted by -F <hconv> option.  Each <field> may be a case-insenstive
      subs-string of fields available.

Options:
  --ecdsa           A slower key-reconstructor based on Elliptic-Curve-Cryptography which:
                      - can recover both AES or BTC[1] private-keys;
                      - can recover keys from any file-type (no need for *magic-bytes*);
                      - yields always a single correct key.
                    For the `crack-fkey` sub-cmd, the <prime-factors> select which public-key
                    to crack (AES or BTC).
  --btc <btc-addr>  Guess BTC private-keys based on the bitcoin-address and BTC[1] public-key.
                      - The <btc-addr> is typically found in the ransom-note or recovery file
                      - The <pub-key> is the BTC key reported by `decrypt` sub-cmd.
  -F <hconv>        Specify print-out format for tesla-header fields (keys, addresses, etc),
                    where <hconv> is any non-ambiguous case-insensitive *prefix* from:

                      - raw: all bytes as-is - no conversion (i.e. hex private-keys NOT strip & l-rotate).
                      - fix: like 'raw', but priv-keys fixed and size:int.
                      - bin: all bytes (even private-keys), priv-keys: fixed.
                      - xhex: all string-HEX, size:bytes-hexed.
                      - hex: all string-hex prefixed with '0x', size: int-hexed.
                      - num: all natural numbers, size: int.
                      - 64: all base64, size(int) - most concise.
                    [default: 64]
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

   teslacrack decrypt -v tesla-file.vvv        ## Decrypt file, and if unknwon key, printed.
   teslacrack crack-fkey tesla-file.vvv 1 3 5  ## Unfacrtor the AES-key of the file from primes 1,3,5.
   teslacrack decrypt .  bar\cob.xlsx          ## Decrypt current-folder & a file
   teslacrack decrypt --delete-old C:\\        ## WILL DELETE ALL `.vvv` files on disk!!!
   teslacrack decrypt                          ## Decrypt current-folder, logging verbosely.
   teslacrack decrypt --progress -n -v  C:\\   ## Just to check what actions will perform.

Enjoy! ;)
"""
from __future__ import print_function

import io
import logging
from teslacrack import decrypt
from teslacrack import key as tckey, teslafile, unfactor

import docopt

import teslacrack as tc


log = tc.log


def init_logging(level=logging.INFO,
                 frmt="%(asctime)-15s:%(levelname)3.3s: %(message)s"):
    logging.basicConfig(level=level, format=frmt)


def _attribufy_opts(opts):
    """
    Attach opts-items as attributes, with dashes L-trimmed, and args normalized.

    OF course they must not class.
    """
    for k, v in opts.items():
        k = k.replace('-', '_')
        if k.startswith('_'):
            setattr(opts, k.lstrip('__'), v)
        elif k.startswith('<'):
            setattr(opts, k[1:-1], v)


def _crack_file_key(opts):
    advice_msg = "\n  Re-validate prime-factors."
    primes = unfactor.validate_primes(opts['<prime-factor>'])
    file = opts['<file>']
    log.info('Guessing keys from tesla-file: %s', file)

    if opts['--btc']:
        key_name = 'BTC'
        key = unfactor.crack_btc_key_from_btc_address(opts['--btc'], primes)
        msg = key and "Found BTC-key: 0x%0.64X" % key
    elif opts['--ecdsa']:
        key_name, key = unfactor.crack_ecdsa_key_from_file(file, primes)
        msg = key and "Found %s-key: 0x%0.64X" % (key_name, key)
    else:
        key_name = 'AES'
        keys = unfactor.crack_aes_keys_from_file(file, primes)
        msg = keys and "Candidate AES-key(s): \n  %s" % '\n  '.join(
                    '0x%0.64X' % key for key in keys)
        advice_msg = "\n  Re-validate prime-factors and/or try another file-type."

    if not msg:
        raise tc.CrackException("Failed reconstructing %s-key! %s" % (key_name, advice_msg))
    return msg


def _crack_key(opts):
    primes = unfactor.validate_primes(opts['<prime-factor>'])
    pubkey = opts['<pub-key>']

    if opts['--btc']:
        key_name = 'BTC'
        key = unfactor.crack_btc_key_from_btc_address(
                opts['--btc'], primes, pubkey)
        msg = key and "Found BTC-key: 0x%0.64X" % key
    elif opts['--ecdsa']:
        key_name = '<AES_or_BTC>'
        ecdsa_secret = tckey.autoconv_key(opts['--ecdsa'])
        key = unfactor.crack_ecdsa_key(ecdsa_secret, pubkey, primes)
        msg = key and "Found ECDSA-key: 0x%0.64X" % key
    else:
        msg = "main() miss-matched *docopt* mutual-exclusive opts (--ecdsa|--btc)! \n  %s"
        raise AssertionError(msg % opts)

    if not msg:
        raise tc.CrackException("Failed reconstructing %s-key! %s"
                "\n  Re-validate prime-factors."% key_name)
    return msg


def _show_file_headers(opts):
    file = opts['<file>']
    hconv = opts['-F']

    fields = teslafile.match_header_fields(opts['<field>'])
    log.info('Reading header-fields %r for tesla-file: %s', fields, file)
    with io.open(file, 'rb') as fd:
        h = teslafile.Header.from_fd(fd)

        h
    if len(fields) == 1:
        res = h.conv(fields[0], hconv)
    else:
        res = '\n'.join('%10.10s: %r' % (k, h.conv(k, hconv))
                for k in h._fields if k in fields)
    return res


def main(*args):
    v = 'teslacrack-%s' % tc.__version__
    opts = docopt.docopt(__doc__, argv=args or None, version=v)

    _attribufy_opts(opts)
    log_level = logging.DEBUG if opts.verbose else logging.INFO
    init_logging(log_level)
    log.debug('Options: %s', opts)

    try:
        if opts['decrypt']:
            opts.fpaths = opts['<path>']
            decrypt.decrypt(opts)
        elif opts['crack-fkey']:
            return _crack_file_key(opts)
        elif opts['crack-key']:
            return _crack_key(opts)
        elif opts['file']:
            return _show_file_headers(opts)
        else:
            msg = "main() miss-matched *docopt* sub-commands! \n  %s"
            raise AssertionError(msg % opts)
    except tc.CrackException as ex:
        log.error("%s", ex)
        exit(-2)

if __name__ == '__main__':
    print(main())
