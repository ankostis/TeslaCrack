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

USAGE:
    teslacrack ls        [options] [--fld=<field>...] [<path>...]
    teslacrack decrypt   [options] [--fld=<field>...]
                                [--dry-run] [--delete | --delete-old]
                                [(--fix | --overwrite) [--backup=<.ext>]] [<path>...]
    teslacrack unfactor  [options] [--ecdh | --btc-addr=<addr>] <file> <prime-factor>...
    teslacrack unfactor  [options] (--pub=<db-key> | --btc-addr=<addr>) <mul-db-key> [<prime-factor>...]
    teslacrack key       [options] [--force] [--delete] [--batch]
                                [--btc | --aes | --master=<db-key>]
                                [--fld=<field-n-value>]... [<db-key>...]
    teslacrack -h | --help
    teslacrack -V | --version

SUB-COMMANDS:
    ls:
        Lists header-fields (keys and their status) from tesla-files in <path> file(s)/folder(s).
        If any unknown keys encountered, searches them in http://factordb.com (unless --no-factordb given).
        Use -C <conv> option to control the formatting of the fields. Use --fld <field> to limit
        what is listed.  If no <path> given, it lists recursively current folder.
    decrypt:
        Decrypts tesla-file(s) in <path> file(s)/folder(s) if their private AES or BTC keys
        already known; behaves like `ls` if any unknown keys encountered; additionally,
        if key fully factored, attempts to unfactor it.
        If no <path> given, it decrypts recursively current folder.
    unfactor (1st form):
       Attempts to reconstruct prv-keys from file on a best effort basis:
       if <prime-factor>s given, they choose which key to attack; otherwise, it reconstructs
       anyone of *BTC* or *AES* prv-key (in that order) with all primes known either
       in the http://factordb.com or in the internal key-db (i.e. set by `ls` or `key` sub-cmds).
       When none of --ecdh or --btc-addr specified, the default method is used,
       so the <file> must belong to `known_file_magic`.
    unfactor (2nd form):
        Like the `unfactor`, above, but the <mul-db-key> is explicitly given and
        the method must be one of *ECDH* or *BTC*.  Use the `ls` or `decrypt` sub-cmds
        to print unknown "mul" keys; factorize them to get all <prime-factor>.
    key:
        List or update the internal key-db at `~/.teslacrack.yaml`.
        Without any --fld, --btc, --aes, --master options, it lists matching  <db-key> record(s)
        or all if non given; Otherwise, it creates new or updates matching key-records
        based on whether <db-key> given.

OPTIONS:
    --pub [<pub-key>]      Reconstruct key based on Elliptic-Curve-Cryptography which:
                             - can recover both AES or BTC[1] keys;
                             - can recover keys from any file-type (no need for *magic-bytes*);
                             - yields always a single correct key.
                           For the 1st form of `unfactor` sub-cmd, the <prime-factors> select which key
                           to crack (AES or BTC). For the 2nd form of `unfactor` sub-cmd, specify
                           which <mul-key> and paired <pub-key> to break.
    --btc-addr <btc-addr>  Guess BTC key based on the bitcoin-address and BTC[1] pub-key.
                           The <btc-addr> is typically found in the ransom-note or recovery file
    --fld=<field>          Any case-insenstive subs-string of tesla-file header-fields.
    -C=<conv>             Specify the print-out format for keys.
                           where <conv> is any non-ambiguous case-insensitive *prefix* from:
                             - raw: all bytes as-is - no conversion (i.e. hex mul-keys NOT strip & l-rotate).
                             - fix: like 'raw', but mul-keys fixed and size:int; fail if mul-keys invalid.
                             - bin: all bytes (even mul-keys), mul-keys: fixed.
                             - xhex: all string-HEX, size:bytes-hexed.
                             - hex: all string-hex prefixed with '0x', size: int-hexed.
                             - num: all natural numbers, size: int.
                             - asc: all base64, size(int) - most concise.
                           [default: hex]
    --no-factordb          Do not search for prime-factors in http://factordb.com.
    --keydb-no-write       Do not update internal key-db at `~/.teslacrack.yaml`.
    --keydb-no-rw          Do not update nor read internal key-db `~/.teslacrack.yaml`.
    -b, --batch            Allow performing `key` subcmd operations on multiple matching keys.
    -f, --force            Force key-db operation, ie overwrite/move keys, delete keyrecs.
    -d, --delete           Delete key-records, or crypted-files after decrypting them.
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
    -v, --verbose          Verbosely log(DEBUG) all actions performed.

NOTES:
    - The <db-key> must match the prefix or name of some key registered in the internal key-db.
      Use the `key` or the `ls <file>` sub-cmds to register keys.
    - The (rough) pattern of usage is this:
        1. Run this cmd on some tesla-files to gather your mul-AES keys;
        2. factorize the mul-key(s) reported, first by searching http://factordb.com/
           and then use *msieve* or *YAFU* external programs to factorize
           any remaining non-prime ones;
        3. use `unfactor` sub-cmd to reconstruct your cleartext keys;
        4. add keys from above into `known_AES_key_pairs`, and then
        5. re-run `decrypt` on all infected file/directories.
    - For ancient versions of TeslaCrypt, use the private BTC-key  with *TeslaDecoder* external program.
    - Check the following for gathering required keys and addresses:
      - http://www.bleepingcomputer.com/virus-removal/teslacrypt-alphacrypt-ransomware-information
      - https://securelist.com/blog/research/71371/teslacrypt-2-0-disguised-as-cryptowall

EXAMPLES:

    teslacrack ls -v tesla-file.vvv             ## Decrypt file, and if unknwon key, printed.
    teslacrack unfactor tesla-file.vvv 1 3 5    ## Unfacrtor the AES-key of the file from primes 1,3,5.
    teslacrack decrypt .  bar\cob.xlsx          ## Decrypt current-folder & a file
    teslacrack decrypt --delete-old C:\\        ## WILL DELETE ALL `.vvv` files on disk!!!
    teslacrack decrypt                          ## Decrypt current-folder, logging verbosely.
    teslacrack decrypt --progress -n -v  C:\\   ## Just to check what actions will perform.

Enjoy! ;)
"""
from __future__ import print_function, division

import logging
from pprint import pformat
from teslacrack import CrackException
from teslacrack import __version__ as tslc_version

import docopt


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
    from teslacrack import unfactor

    advice_msg = "\n  Re-validate prime-factors."
    primes = unfactor.validate_primes(opts['<prime-factor>'])
    file = opts['<file>']
    log.info('Guessing keys from tesla-file: %s', file)

    if opts['--btc-addr']:
        key_name = 'BTC'
        key = unfactor.crack_btc_key_from_btc_address(opts['--btc-addr'], primes)
        msg = key and "Found BTC-key: 0x%064X" % key
    elif opts['--ecdh']:
        key_name, key = unfactor.crack_ecdh_key_from_file(file, primes)
        msg = key and "Found %s-key: 0x%064X" % (key_name, key)
    else:
        key_name = 'AES'
        key = unfactor.crack_aes_key_from_file(file, primes)
        msg = key and "AES-key: %s" % key
        advice_msg = "\n  Re-validate prime-factors and/or try another file-type."

    if not msg:
        raise CrackException("Failed reconstructing %s-key! %s" % (key_name, advice_msg))
    return msg


def _crack_key(opts):
    from teslacrack import keyconv, unfactor

    primes = unfactor.validate_primes(opts['<prime-factor>'])
    mul_key = keyconv.AKey.auto(opts['<mul-key>'])

    if opts['--btc-addr']:
        key_name = 'BTC'
        key = unfactor.crack_btc_key_from_btc_address(
                opts['--btc-addr'], primes, mul_key)
        msg = key and "Found BTC-key: 0x%064X" % key
    elif opts['--ecdh']:
        key_name = '<AES_or_BTC>'
        ecdh_pub = keyconv.AKey.auto(opts['--ecdh'])
        key = unfactor.crack_ecdh_key(ecdh_pub, mul_key, primes)
        msg = key and "Found ECDH private-key: 0x%064X" % key
    else:
        msg = "main() miss-matched *docopt* mutual-exclusive opts (--ecdh|--btc-addr)! \n  %s"
        raise AssertionError(msg % opts)

    if not msg:
        raise CrackException("Failed reconstructing %s-key! %s"
                "\n  Re-validate prime-factors."% key_name)
    return msg


def _show_file_headers(opts):
    from teslacrack import teslafile

    fpaths = opts['<path>']
    fld_substrs = opts['--fld']
    conv = opts['-C']

    fields = fld_substrs and teslafile.match_substr_to_fields(fld_substrs)
    res = teslafile.fetch_file_headers(fpaths, fields, conv)
    if len(res) == 1:
        res = res[0]
    return res


def _get_or_set_keys(opts):
    from teslacrack import keydb

    dbkeys = opts['<db-key>']
    fields = opts['--fld']
    db = keydb.load()
    krng = keydb.KeyRing(db)
    if opts['--delete']:
        res = krng.del_keyrec_field(dbkeys, fields, opts['--batch'], opts['--force'])
    else:
        keyrecs = krng.get_keyrec_fields(dbkeys, fields=fields)
        res = keyrecs
    return res


def main(*args):
    v = 'teslacrack-%s' % tslc_version
    opts = docopt.docopt(__doc__, argv=args or None, version=v)

    _attribufy_opts(opts)
    log_level = logging.DEBUG if opts.verbose else logging.INFO
    init_logging(log_level)
    log.debug('Options: %s', opts)

    try:
        if opts['ls']:
            return pformat(_show_file_headers(opts), indent=2)
        elif opts['key']:
            return pformat(_get_or_set_keys(opts), indent=2)
        elif opts['decrypt']:
            from teslacrack import decrypt

            opts.fpaths = opts['<path>']
            decrypt.decrypt(opts)
        elif opts['unfactor']:
            return _crack_file_key(opts)
        elif opts['unfactor']:
            return _crack_key(opts)
        else:
            msg = "main() miss-matched *docopt* sub-commands! \n  %r"
            raise AssertionError(msg % opts)
    except CrackException as ex:
        log.error("%s", ex)
        exit(-2)

if __name__ == '__main__':
    print(main())
