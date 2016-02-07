import base64
import binascii
import codecs
import logging
import re


__version__ = '1.0.0'

tesla_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

class CrackException(Exception):
    pass


log = logging.getLogger('teslacrypt')


def init_logging(level=logging.INFO,
        frmt="%(asctime)-15s:%(levelname)3.3s: %(message)s"):
    logging.basicConfig(level=level, format=frmt)


def lalign_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def fix_int_key(int_key):
    return lalign_key(binascii.unhexlify('%064x' % int_key))


def fix_hex_key(hex_key):
    return lalign_key(binascii.unhexlify(hex_key))


def guess_binary(data):
    """Returns bytes after trying various transforms on the data."""
    if isinstance(data, bytes):
        funcs = [binascii.unhexlify, base64.b64decode, lambda d: d]
    else:
        funcs = [lambda d: binascii.unhexlify('%x'%int(d)),
                binascii.unhexlify, base64.b64decode,
                lambda d: codecs.raw_unicode_escape_encode(d)[0]]
    for f in funcs:
        try:
            res = f(data)
            log.debug("Guessed bin-data(%s) --> %s(%s)", data, f, res)
            if len(res) >= 8:
                return res
        except:
            pass
    raise ValueError('Cannot guess binary-data: %s' % data)


def main(*args):
    log_level = logging.DEBUG if 1 else logging.INFO
    init_logging(log_level)
    raise NotImplementedError()


if __name__ == '__main__':
    main()
