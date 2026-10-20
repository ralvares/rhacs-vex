"""Mirror Red Hat's CSAF-VEX feed into data/vex, then update the index.

    archive_latest.txt   → the dated .tar.zst of the whole corpus (first sync)
    changes.csv          → every file with its last change: fetch what is newer
    deletions.csv        → files Red Hat withdrew: remove them

Local files are named CVE-YYYY-NNNN.json.gz (gzip: the corpus is ~22 GB as
plain JSON, ~1.2 GB compressed) and carry Red Hat's change time as their
mtime, which is how the next sync (and the index) know what changed. Plain
.json files from an older mirror are compressed in place on the next sync.
"""
from __future__ import annotations

import calendar
import csv
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

FEED = os.environ.get('VEXTRIAGE_FEED', 'https://security.access.redhat.com/data/csaf/v2/vex')
_NAME = re.compile(r'(cve-\d{4}-\d+)\.json$', re.I)
_FILE = re.compile(r'^(CVE-\d{4}-\d+)\.json(\.gz)?$', re.I)


def files(vex_dir: str) -> dict:
    """{CVE: path} of the mirror (.json.gz, or a plain .json not yet compressed)."""
    out: dict = {}
    for f in os.listdir(vex_dir):
        m = _FILE.match(f)
        if m and (m.group(2) or m.group(1).upper() not in out):
            out[m.group(1).upper()] = os.path.join(vex_dir, f)
    return out


def load(path: str) -> dict:
    """One mirror file, parsed."""
    with (gzip.open(path, 'rb') if path.endswith('.gz') else open(path, 'rb')) as fh:
        return json.load(fh)


def _session():
    import requests
    s = requests.Session()
    s.headers['User-Agent'] = 'vextriage'
    return s


def _get(session, url: str, stream: bool = False, tries: int = 4):
    delay = 2
    for i in range(tries):
        try:
            r = session.get(url, timeout=120, stream=stream)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r
        except Exception:
            if i == tries - 1:
                raise
            time.sleep(delay)
            delay *= 2


def _ts(s: str) -> float:
    m = re.match(r'(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})', s or '')
    return float(calendar.timegm(tuple(map(int, m.groups())))) if m else 0.0


def _local(vex_dir: str, remote: str) -> str:
    m = _NAME.search(remote)
    return os.path.join(vex_dir, m.group(1).upper() + '.json.gz') if m else ''


def _csv(session, name: str) -> list:
    r = _get(session, f'{FEED}/{name}')
    if r is None:
        return []
    return [row for row in csv.reader(io.StringIO(r.text)) if row and _NAME.search(row[0])]


def _write(path: str, data: bytes, mtime: float):
    """Store a document gzipped, stamped with Red Hat's change time."""
    tmp = path + '.tmp'
    with open(tmp, 'wb') as fh:
        fh.write(gzip.compress(data, 6, mtime=0))
    os.replace(tmp, path)
    if mtime:
        os.utime(path, (mtime, mtime))
    plain = path[:-3] if path.endswith('.gz') else ''
    if plain and os.path.exists(plain):
        os.unlink(plain)


def _compress_plain(vex_dir: str, workers: int, log) -> int:
    """An older mirror's plain .json files → .json.gz, keeping their mtime."""
    plain = [os.path.join(vex_dir, f) for f in os.listdir(vex_dir)
             if _FILE.match(f) and not f.endswith('.gz')]
    if not plain:
        return 0
    log(f'compressing {len(plain):,} plain .json files …')

    def one(path):
        with open(path, 'rb') as fh:
            _write(path + '.gz', fh.read(), os.path.getmtime(path))
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(one, plain))
    return len(plain)


def _unpack_archive(session, vex_dir: str, log) -> float:
    """Extract the dated archive into vex_dir; returns the archive's date (epoch)."""
    ptr = _get(session, f'{FEED}/archive_latest.txt')
    if ptr is None:
        raise RuntimeError('archive_latest.txt not found')
    name = ptr.text.strip().split()[0]
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})', name)
    cut = float(calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)), 0, 0, 0))) if m else 0.0
    log(f'downloading {name} …')
    fd, tmp = tempfile.mkstemp(dir=vex_dir, suffix='.tar.zst')
    try:
        with os.fdopen(fd, 'wb') as fh:
            r = _get(session, f'{FEED}/{name}', stream=True)
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
        log('unpacking …')
        n = 0
        for member, data in _tar_members(tmp):
            path = _local(vex_dir, member.name)
            if path:
                _write(path, data, member.mtime or cut)
                n += 1
        log(f'{n:,} documents from the archive')
    finally:
        os.unlink(tmp)
    return cut


def _tar_members(path: str):
    try:
        import zstandard
        with open(path, 'rb') as fh:
            reader = zstandard.ZstdDecompressor().stream_reader(fh)
            with tarfile.open(fileobj=reader, mode='r|') as tf:
                for m in tf:
                    if m.isfile():
                        yield m, tf.extractfile(m).read()
        return
    except ImportError:
        pass
    if not shutil.which('zstd'):
        raise RuntimeError('need the zstandard Python package or the zstd command to unpack the archive')
    proc = subprocess.Popen(['zstd', '-dc', path], stdout=subprocess.PIPE)
    with tarfile.open(fileobj=proc.stdout, mode='r|') as tf:
        for m in tf:
            if m.isfile():
                yield m, tf.extractfile(m).read()
    proc.wait()


def mirror(vex_dir: str, full: bool = False, workers: int = 8, log=print) -> dict:
    """Bring vex_dir up to date with Red Hat's feed."""
    os.makedirs(vex_dir, exist_ok=True)
    session = _session()
    _compress_plain(vex_dir, workers, log)
    have = files(vex_dir)
    cut = None
    if full or len(have) < 1000:
        try:
            cut = _unpack_archive(session, vex_dir, log)
        except Exception as e:                       # fall back to file by file
            log(f'archive unavailable ({e}); fetching files one by one')
    changes = _csv(session, 'changes.csv')
    todo = []
    for remote, stamp, *_ in changes:
        path = _local(vex_dir, remote)
        t = _ts(stamp)
        if not path:
            continue
        if not os.path.exists(path) or os.path.getmtime(path) < t:
            todo.append((remote, path, t))
    log(f'{len(todo):,} documents changed upstream')

    def fetch(item):
        remote, path, t = item
        r = _get(session, f'{FEED}/{remote}')
        if r is not None:
            _write(path, r.content, t)
            return 1
        return 0
    got = 0
    with ThreadPoolExecutor(workers) as ex:
        for i, n in enumerate(ex.map(fetch, todo), 1):
            got += n
            if i % 500 == 0:
                log(f'  {i:,}/{len(todo):,}')
    removed = 0
    for remote, *_ in _csv(session, 'deletions.csv'):
        path = _local(vex_dir, remote)
        for p in (path, path[:-3]) if path else ():
            if os.path.exists(p):
                os.unlink(p)
                removed += 1
    return {'fetched': got, 'removed': removed, 'documents': len(files(vex_dir))}
