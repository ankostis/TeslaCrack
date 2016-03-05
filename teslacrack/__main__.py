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
"""
from __future__ import print_function, division

import io
import logging

import docopt

import teslacrack as tslc


log = logging.getLogger('teslacrack.main')


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
    primes = tslc.unfactor.validate_primes(opts['<prime-factor>'])
    file = opts['<file>']
    log.info('Guessing keys from tesla-file: %s', file)

    if opts['--btc-addr']:
        key_name = 'BTC'
        key = tslc.unfactor.crack_btc_key_from_btc_address(opts['--btc-addr'], primes)
        msg = key and "Found BTC-key: 0x%064X" % key
    elif opts['--ecdh']:
        key_name, key = tslc.unfactor.crack_ecdh_key_from_file(file, primes)
        msg = key and "Found %s-key: 0x%064X" % (key_name, key)
    else:
        key_name = 'AES'
        key = tslc.unfactor.crack_aes_key_from_file(file, primes)
        msg = key and "AES-key: %s" % key
        advice_msg = "\n  Re-validate prime-factors and/or try another file-type."

    if not msg:
        raise tslc.CrackException("Failed reconstructing %s-key! %s" % (key_name, advice_msg))
    return msg


def _crack_key(opts):
    primes = tslc.unfactor.validate_primes(opts['<prime-factor>'])
    mul_key = tslc.keyconv.autoconv_to_bytes(opts['<mul-key>'])

    if opts['--btc-addr']:
        key_name = 'BTC'
        key = tslc.unfactor.crack_btc_key_from_btc_address(
                opts['--btc-addr'], primes, mul_key)
        msg = key and "Found BTC-key: 0x%064X" % key
    elif opts['--ecdh']:
        key_name = '<AES_or_BTC>'
        ecdh_pub = tslc.keyconv.autoconv_to_bytes(opts['--ecdh'])
        key = tslc.unfactor.crack_ecdh_key(ecdh_pub, mul_key, primes)
        msg = key and "Found ECDH private-key: 0x%064X" % key
    else:
        msg = "main() miss-matched *docopt* mutual-exclusive opts (--ecdh|--btc-addr)! \n  %s"
        raise AssertionError(msg % opts)

    if not msg:
        raise tslc.CrackException("Failed reconstructing %s-key! %s"
                "\n  Re-validate prime-factors."% key_name)
    return msg


def _show_file_headers(opts):
    file = opts['<file>']
    substr = opts['<field>']
    conv = opts['-F']
    with io.open(file, 'rb') as fd:
        h = tslc.teslafile.Header.from_fd(fd)
    fields = h.matchAll(substr)
    if not fields:
        raise tslc.CrackException('Substring %r matched %i header field: %r' %
                (substr, len(fields), list(fields)))

    if len(fields) == 1:
        res = next(iter(fields)).conv(conv)
    else:
        res = '\n'.join('%15.15s: %s' % (k, v.conv(conv)) for k, v in fields)
    return res


def main(*args):
    v = 'teslacrack-%s' % tslc.__version__
    opts = docopt.docopt(__doc__, argv=args or None, version=v)

    _attribufy_opts(opts)
    log_level = logging.DEBUG if opts.verbose else logging.INFO
    init_logging(log_level)
    log.debug('Options: %s', opts)

    try:
        if opts['decrypt']:
            opts.fpaths = opts['<path>']
            tslc.decrypt.decrypt(opts)
        elif opts['crack-fkey']:
            return _crack_file_key(opts)
        elif opts['crack-key']:
            return _crack_key(opts)
        elif opts['file']:
            return _show_file_headers(opts)
        else:
            msg = "main() miss-matched *docopt* sub-commands! \n  %s"
            raise AssertionError(msg % opts)
    except tslc.CrackException as ex:
        log.error("%s", ex)
        exit(-2)

if __name__ == '__main__':
    print(main())
