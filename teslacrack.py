# TeslaCrypt cracker
#
# by Googulator
#
# To use, factor the 2nd hex string found in the headers of affected files using msieve.
# The AES-256 key will be one of the factors, typically not a prime - experiment to see which one works.
# Insert the hex string & AES key below, under known_AES_key_pairs, then run on affected directory.
# If an unknown key is reported, crack that one using msieve, then add to known_AES_key_pairs and re-run.
#
# This script requires pycrypto to be installed.
#
#    python teslacrypt.py [options] [file-path-1]...
#
# When invoked without any folder specified, working-dir('.') assumed.
#
## OPTIONS
#    --       # Delete encrypted-files after decrypting them.
#    ---old   # Delete encrypted even if decrypted-file created during a previous run
#    --    # Re-decrypt and overwirte existing decrypted-files.
#    --progress     # Before start encrypting, pre-scan all dirs, to provide progress-indicator.
#    -v             # Verbosely log(DEBUG) all files decrypted
#    -n             # Dry-run: do not decrypt/, just report actions performed (logs and stats).

## EXAMPLES:
#
#    python teslacrack -v                      ## Decrypts current-folder, logging verbosely.
#    python teslacrack .  bar\cob.xlsx         ## Decrypts current-folder & file
#    python teslacrack ---old C:\\       ## WILL DELETE ALL `.vvv` files on disk!!!
#    python teslacrack --progress -n -v  C:\\  ## Just to check what actions will perform.
#
# Enjoy! ;)

from __future__ import unicode_literals
import functools as ft
import itertools as itt
import multiprocessing as mp
from multiprocessing import Process, Queue, JoinableQueue, Value  # @UnresolvedImport
from queue import Empty, Full
from ctypes import Structure, c_long, c_wchar_p
import logging
import os
import platform
import struct
import sys
import time

from Crypto.Cipher import AES
from collections import namedtuple


log = logging.getLogger('teslacrack')
#log = get_logger()

## Add your (encrypted-AES-key: reconstructed-AES-key) pair(s) here,
#  like the examples below:
#
known_AES_key_pairs = {
    b'D4E0010A8EDA7AAAE8462FFE9562B29871B9DA186D98B5B15EC9F77803B60EAB12ADDF78CBD4D9314A0C31270CC8822DCC071D10193D1E612360B26582DAF124': b'\xEA\x68\x5A\x3C\xDB\x78\x0D\xF2\x12\xEB\xAA\x50\x03\xAD\xC3\xE1\x04\x06\x3E\xBC\x25\x93\x52\xC5\x09\x88\xB7\x56\x1A\xD1\x34\xA5',
    b'9F2874FB536C0A6EF7B296416A262A8A722A38C82EBD637DB3B11232AE0102153C18837EFB4558E9E2DBFC1BB4BE799AE624ED717A234AFC5E2F8E2668C76B6C': b'\xCD\x0D\x0D\x54\xC4\xFD\xB7\x64\x7C\x4D\xB0\x95\x6A\x30\x46\xC3\x4E\x38\x5B\x51\xD7\x35\xD1\x7C\x00\x9D\x47\x3E\x02\x84\x27\x95',
    b'115DF08B0956AEDF0293EBA00CCD6793344D6590D234FE0DF2E679B7159E8DB05F960455F17CDDCE094420182484E73D4041C39531B5B8E753E562910561DE52': b'\x1A\xDC\x91\x33\x3E\x8F\x6B\x59\xBB\xCF\xB3\x34\x51\xD8\xA3\xA9\x4D\x14\xB3\x84\x15\xFA\x33\xC0\xF7\xFB\x69\x59\x20\xD3\x61\x8F',
    b'7097DDB2E5DD08950D18C263A41FF5700E7F2A01874B20F402680752268E43F4C5B7B26AF2642AE37BD64AB65B6426711A9DC44EA47FC220814E88009C90EA': b'\x01\x7b\x16\x47\xd4\x24\x2b\xc6\x7c\xe8\xa6\xaa\xec\x4d\x8b\x49\x3f\x35\x51\x9b\xd8\x27\x75\x62\x3d\x86\x18\x21\x67\x14\x8d\xd9',
}

tesla_extensions = ['.vvv', '.ccc']  # Add more known extensions.

known_file_magics = [b'\xde\xad\xbe\xef\x04', b'\x00\x00\x00\x00\x04']

PROGRESS_INTERVAL_SEC = 1.7 # Log stats every that many files processed.
MAX_REPORT_ITEMS = 15

unknown_key_pairs = set() # Unknown key-pairs (AES, BTC) encountered while scanning.

class Opts(object):pass

class Stats(Structure):
    _fields_ = [
        ('scanned_nfiles', c_long),
        ('tesla_nfiles', c_long),
        ('visited_nfiles', c_long),
        ('encrypt_nfiles', c_long),
        ('decrypt_nfiles', c_long),
        ('overwrite_nfiles', c_long),
        ('deleted_nfiles', c_long),
        ('skip_nfiles', c_long),
    ]

class QueueMachine(object):
    """A map of {queue_name --> (queue, items-pumped, title, desc)}."""
    def __init__(self, queue_names):
        self._qmap = qmap = {qn: [Queue(), [], title, desc]
                for qn, title, desc in queue_names}
        self.queues = {qn: rec[0] for qn, rec in qmap.items()}
        self.dicts = {qn: rec[1] for qn, rec in qmap.items()}
        self.titles = {qn: rec[2] for qn, rec in qmap.items()}
        self.descs = {qn: rec[3] for qn, rec in qmap.items()}
    def pump(self):
        for qn, rec in self._qmap.items():
            _queue_to_list(rec[0], rec[1])


def _queue_to_list(q, l=None):
    if l is None:
        l = []
    try:
        for i in iter(lambda: q.get_nowait(), None):
            l.append(i)
    except Empty:
        pass
    return l


def _peek_queue(q, not_found=None):
    try:
        v = q.get_nowait()
        q.put(v)
        return v
    except Empty:
        return not_found


def _fix_key(key):
    while key[0] == b'\0':
        key = key[1:] + b'\0'
    return key


def is_tesla_file(fname):
    return os.path.splitext(fname)[1] in tesla_extensions

def _needs_decryption(fpath, exp_size, overwrite, badorigs_q):
    """Decides `True` if missing, size-corrupted, or forced-overwrite."""
    fexists = os.path.isfile(fpath)
    if fexists and not overwrite:
        disk_size = os.stat(fpath).st_size
        if disk_size != exp_size:
            overwrite = True
            badorigs_q.put(fpath)
    return fexists, overwrite

def _get_decrypted_AES_key(fpath, header, unknowns_q, unknown_keys_q):
    """Search if encrypted-AES-key is known, and maintains related indexes."""
    aes_encrypted_key = header[0x108:0x188].rstrip(b'\0')
    aes_key = known_AES_key_pairs.get(aes_encrypted_key)
    if not aes_key:
        unknowns_q.put(fpath)
        btc_encrypted_key = header[0x45:0xc5].rstrip(b'\0')
        keys_pair = aes_encrypted_key, btc_encrypted_key
        if keys_pair not in unknown_key_pairs:
            unknown_keys_q.add(keys_pair)
        unknown_key_pairs.add(keys_pair)

    return aes_key

def decrypt_tesla_file(opts, fpath, stats, invalids_q, badorigs_q, unknowns_q, fails_q,
                unknown_keys_q, **report_qs):
    try:
        stats.visited_nfiles += 1
        do_unlink = False
        with open(fpath, "rb") as fin:
            header = fin.read(414)

            if header[:5] not in known_file_magics:
                invalids_q.put(fpath)
                return
            stats.encrypt_nfiles += 1

            aes_key = _get_decrypted_AES_key(
                    fpath, header, unknowns_q, unknown_keys_q)
            if not aes_key:
                return

            size = struct.unpack('<I', header[0x19a:0x19e])[0]
            orig_fname = os.path.splitext(fpath)[0]
            decrypted_exists, should_decrypt = _needs_decryption(
                    orig_fname, size, opts.overwrite, badorigs_q)
            if should_decrypt:
                log.debug("Decrypting%s%s: %s",
                        '(overwrite)' if decrypted_exists else '',
                        '(dry-run)' if opts.dry_run else '', fpath)
                decryptor = AES.new(
                        _fix_key(aes_key),
                        AES.MODE_CBC, header[0x18a:0x19a])
                data = decryptor.decrypt(fin.read())[:size]
                if not opts.dry_run:
                    with open(orig_fname, 'wb') as fout:
                        fout.write(data)
                ## When decrypted was corrupted, `--delete` should not remove .vvv -
                #  use `--delete-old` to force that.
                if opts.delete and not decrypted_exists or opts.delete_old:
                    do_unlink = True
                stats.decrypt_nfiles += 1
                stats.overwrite_nfiles += decrypted_exists
            else:
                log.debug("Skip %r, already decrypted.", fpath)
                stats.skip_nfiles += 1
                if opts.delete_old:
                    do_unlink = True
        if do_unlink:
            log.debug("Deleting%s: %s",
                    '(dry-run)' if opts.dry_run else '', fpath)
            if not opts.dry_run:
                os.unlink(fpath)
            stats.deleted_nfiles += 1
    except Exception as e:
        fails_q.put('%r: %s' % (e, fpath))


def log_report_qs(queue_items, queue_titles):
    for qn, items in sorted(queue_items.items()):
        if items:
            if len(items) > MAX_REPORT_ITEMS:
                items = items[:MAX_REPORT_ITEMS] + ['...']
            log.info("+++'%s' files: \n  %s",
                    queue_titles[qn], '\n  '.join(items))


def log_unknown_keys(unknown_keys):
    if unknown_keys:
        #assert len(aes_unknown_keys) == len(btc_unknown_keys, ( aes_unknown_keys, btc_unknown_keys)
        log.info("+++Encountered %i unknown-key(s): \n%s"
                "  To crack them, use `msieve` on AES-key(s) or `msieve`+`TeslaDecoder` on Bitcoin-key(s).",
                len(unknown_keys),
                '\n'.join("    AES: %r\n    BTC: %r\n" % (aes, btc)
                        for (aes, btc) in unknown_keys))



def log_stats(fpath, stats, noaccess_q, invalids_q, unknowns_q, fails_q, badorigs_q,
        unknown_keys_q, **report_items):
    """Prints #-of-file without pumping queues (just their length), or from `stats`."""
    dir_progress = ('' if stats.tesla_nfiles <= 0 else
            '(%0.2f%%)' % (100 * stats.visited_nfiles / stats.tesla_nfiles))
    log.info("+++Process%s: %s"
             "\n  Scanned   :%7i"
             "\n  NoAccess  :%7i"
             "\n  TeslaExt  :%7i"
             "\n    Visited   :%7i"
             "\n      Invalid :%7i"
             "\n      Encrypted :%7i"
             "\n        Decrypted :%7i"
             "\n          Overwritten:%7i"
             "\n          BadOrigs   :%7i"
             "\n          Deleted    :%7i"
             "\n        Skipped   :%7i"
             "\n          Unknowns:%7i"
             "\n        Failed    :%7i"
             "\n\n  Missing-Keys:%i"
        , dir_progress, fpath,
        stats.scanned_nfiles, len(noaccess_q), stats.tesla_nfiles,
        stats.visited_nfiles, len(invalids_q), stats.encrypt_nfiles,
        stats.decrypt_nfiles, stats.overwrite_nfiles, len(badorigs_q),
        stats.deleted_nfiles, stats.skip_nfiles, len(unknowns_q),
        len(fails_q),
        len(unknown_keys_q))


def collect_tesla_files(fpaths, fpaths_q, stats, noaccess_q):
    """Collects all files with TeslaCrypt ext containd in :data:`tesla_extensions` (`.vvv`). """
    try:
        def handle_bad_subdir(err):
            pass#noaccess_q.put('%r: %s', err, err.filename)


        _upath = (lambda f: r'\\?\%s' % os.path.abspath(f)
                if platform.system() == 'Windows' else lambda f: f)

        for fpath in fpaths:
            fpath = _upath(fpath)
            if os.path.isfile(fpath) and is_tesla_file(fpath):
                fpaths_q.put(fpath)
                stats.tesla_nfiles += 1
            else:
                for dirpath, subdirs, files in os.walk(fpath, onerror=handle_bad_subdir):
                    stats.scanned_nfiles += len(files)
                    tesla_files = [os.path.join(dirpath, f) for f in files
                            if is_tesla_file(f)]
                    stats.tesla_nfiles += len(tesla_files)
                    for f in tesla_files:
                        fpaths_q.put(fpath)
    finally:
        # `None` signals Collector has finished.
        fpaths_q.put(None)


def process_tesla_files(opts, fpaths_q, stats, report_qs):
    # `None` signals Collector has finished.
    for fpath in iter(lambda: fpaths_q.get(), None):
        try:
            decrypt_tesla_file(opts, fpath, stats, **report_qs)
        finally:
            fpaths_q.task_done()


def main(args):
    fpaths = []

    opts = Opts()
    stats = Value(Stats, lock=False)

    log_level = logging.INFO
    verbose = False
    for arg in args:
        if arg == "--delete":
            opts.delete = True
        elif arg == "--delete-old":
            opts.delete_old = delete_old = True
        elif arg == "--overwrite":
            opts.overwrite = True
        elif arg == "-n":
            opts.dry_run = True
        elif arg == "-v":
            log_level = logging.DEBUG
            verbose = True
        else:
            fpaths.append(arg)

    frmt = "%(asctime)-15s:%(levelname)3.3s: %(message)s"
    logging.basicConfig(level=log_level, format=frmt)
    if verbose or 1:
        mp.log_to_stderr()

    if not fpaths:
        fpaths.append('.')

    fpaths_q  = JoinableQueue()
    qm = QueueMachine([
        ('noaccess_q',
                'no_access',
                "Files (and errors) collector failed to access."),
        ('invalids_q',
                'bad_tesla_header',
                "Tesla-files with invalid content (wrong magic-number)."),
        ('unknowns_q',
                'undecrypted_yet',
                "Files with unknown AES/BTC keys."),
        ('badorigs_q',
                'bad_originals',
                "Corrupted original-files (size-mismatch) to be overwritten."),
        ('fails_q',
                'failed_decryption',
                "Files (and errors) decrypting failed (corrupted '.vvv' file)"),
        ('unknown_keys_q',
                'undecrypted_keys',
                "Pairs of unknown (AES, BTC) keys encountered."),
    ])

    collector = Process(name='Collector',
            target=collect_tesla_files,
            args=(fpaths, fpaths_q, stats, qm.queues['noaccess_q']))
    decryptor = Process(name='Decryptor',
            target=process_tesla_files,
            args=(opts, fpaths_q, stats, qm.queues))
    collector.daemon = True
    decryptor.daemon = True
    collector.start()
    decryptor.start()

    while decryptor.is_alive():
        qm.pump()
        log_stats(_peek_queue(fpaths_q, '<IDLING>'), stats, **qm.dicts)
        log_unknown_keys(qm.dicts['unknown_keys_q'])
        decryptor.join(PROGRESS_INTERVAL_SEC)

    qm.pump()
    log_stats('<FINSIHED>', stats, **qm.dicts)
    log_report_qs(qm.dicts, qm.titles)
    log_unknown_keys(qm.dicts['unknown_keys_q'])

    #collector.join() NO, must dies if decryptor dies.
    decryptor.join()

    if collector.exitcode:
        log.error("Collector crashed!")
    if decryptor.exitcode:
        log.error("Decryptor crashed!")

# log.info("File NOT TeslaCrypted: %s", path)
# log.warn("UNKNOWN key in file: %s", path)
# log.error("Decrypting %r FAILED due to %r!  Please try again.", path, e, exc_info=verbose)

if __name__=='__main__':
    main(sys.argv[1:])
