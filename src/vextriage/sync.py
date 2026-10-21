"""Mirror Red Hat's CSAF-VEX feed into one SQLite file (data/vex.sqlite).

    archive_latest.txt   → the dated .tar.zst of the whole corpus (first sync)
    changes.csv          → every document with its last change: fetch what is newer
    deletions.csv        → documents Red Hat withdrew: remove them

    raw(cve, mtime, gz)  each document gzipped (the corpus is ~22 GB as plain JSON,
                         ~1.2 GB compressed), stamped with Red Hat's change time —
                         how the next sync and the index know what changed

A mirror kept as a directory of CVE-….json[.gz] files (vextriage before this
format) is imported on the next sync and the directory removed.
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
import sqlite3
import subprocess
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

FEED = os.environ.get('VEXTRIAGE_FEED', 'https://security.access.redhat.com/data/csaf/v2/vex')
_NAME = re.compile(r'(cve-\d{4}-\d+)\.json$', re.I)
_FILE = re.compile(r'^(CVE-\d{4}-\d+)\.json(\.gz)?$', re.I)


class Mirror:
    """The local copy of the feed: one row per document."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute('CREATE TABLE IF NOT EXISTS raw (cve TEXT PRIMARY KEY, mtime REAL, gz BLOB)')

    def stamps(self) -> dict:
        """{CVE: Red Hat's change time}."""
        return dict(self.db.execute('SELECT cve, mtime FROM raw'))

    def count(self) -> int:
        return self.db.execute('SELECT COUNT(*) FROM raw').fetchone()[0]

    def put(self, rows: Iterable[tuple]) -> int:
        """rows: (cve, plain JSON bytes, mtime)."""
        n = 0
        for cve, data, mtime in rows:
            self.db.execute('INSERT OR REPLACE INTO raw VALUES (?,?,?)',
                            (cve.upper(), mtime, gzip.compress(data, 6, mtime=0)))
            n += 1
        self.db.commit()
        return n

    def delete(self, cves: Iterable[str]) -> int:
        n = 0
        for cve in cves:
            n += self.db.execute('DELETE FROM raw WHERE cve = ?', (cve.upper(),)).rowcount
        self.db.commit()
        return n

    def load(self, cve: str) -> Optional[dict]:
        row = self.db.execute('SELECT gz FROM raw WHERE cve = ?', (cve.upper(),)).fetchone()
        return json.loads(gzip.decompress(row[0])) if row else None

    def rows(self, cves: Iterable[str]):
        """(cve, mtime, gz) for each CVE asked."""
        for cve in cves:
            row = self.db.execute('SELECT cve, mtime, gz FROM raw WHERE cve = ?', (cve,)).fetchone()
            if row:
                yield row

    def import_dir(self, vex_dir: str, log=print) -> int:
        """A mirror kept as files (CVE-….json.gz / .json, mtime = change time) → rows."""
        paths: dict = {}
        for f in os.listdir(vex_dir):
            m = _FILE.match(f)
            if m and (m.group(2) or m.group(1).upper() not in paths):
                paths[m.group(1).upper()] = os.path.join(vex_dir, f)
        log(f'importing {len(paths):,} documents from {vex_dir} …')
        n = 0
        for cve, p in sorted(paths.items()):
            with open(p, 'rb') as fh:
                data = fh.read()
            gz = data if p.endswith('.gz') else gzip.compress(data, 6, mtime=0)
            self.db.execute('INSERT OR REPLACE INTO raw VALUES (?,?,?)', (cve, os.path.getmtime(p), gz))
            n += 1
            if n % 5000 == 0:
                self.db.commit()
        self.db.commit()
        return n


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


def _cve(remote: str) -> str:
    m = _NAME.search(remote)
    return m.group(1).upper() if m else ''


def _csv(session, name: str) -> list:
    r = _get(session, f'{FEED}/{name}')
    if r is None:
        return []
    return [row for row in csv.reader(io.StringIO(r.text)) if row and _NAME.search(row[0])]


def _unpack_archive(session, mirror: Mirror, log) -> None:
    """The dated archive → the mirror."""
    ptr = _get(session, f'{FEED}/archive_latest.txt')
    if ptr is None:
        raise RuntimeError('archive_latest.txt not found')
    name = ptr.text.strip().split()[0]
    m = re.search(r'(\d{4})-(\d{2})-(\d{2})', name)
    cut = float(calendar.timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)), 0, 0, 0))) if m else 0.0
    log(f'downloading {name} …')
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(mirror.path) or '.', suffix='.tar.zst')
    try:
        with os.fdopen(fd, 'wb') as fh:
            r = _get(session, f'{FEED}/{name}', stream=True)
            for chunk in r.iter_content(1 << 20):
                fh.write(chunk)
        log('unpacking …')
        batch, n = [], 0
        for member, data in _tar_members(tmp):
            cve = _cve(member.name)
            if cve:
                batch.append((cve, data, member.mtime or cut))
            if len(batch) >= 2000:
                n += mirror.put(batch)
                batch = []
        n += mirror.put(batch)
        log(f'{n:,} documents from the archive')
    finally:
        os.unlink(tmp)


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


def mirror(path: str, full: bool = False, workers: int = 8, log=print, legacy_dir: str = '') -> dict:
    """Bring the mirror at `path` up to date with Red Hat's feed."""
    mr = Mirror(path)
    if legacy_dir and os.path.isdir(legacy_dir) and mr.count() == 0:
        if mr.import_dir(legacy_dir, log):
            shutil.rmtree(legacy_dir)
            log(f'{legacy_dir} imported into {path} and removed')
    session = _session()
    if full or mr.count() < 1000:
        try:
            _unpack_archive(session, mr, log)
        except Exception as e:                       # fall back to document by document
            log(f'archive unavailable ({e}); fetching documents one by one')
    have = mr.stamps()
    todo = []
    for remote, stamp, *_ in _csv(session, 'changes.csv'):
        cve, t = _cve(remote), _ts(stamp)
        if cve and (cve not in have or have[cve] < t):
            todo.append((remote, cve, t))
    log(f'{len(todo):,} documents changed upstream')

    def fetch(item):
        remote, cve, t = item
        r = _get(session, f'{FEED}/{remote}')
        return (cve, r.content, t) if r is not None else None
    got, batch = 0, []
    with ThreadPoolExecutor(workers) as ex:
        for i, res in enumerate(ex.map(fetch, todo), 1):
            if res is not None:
                batch.append(res)
            if len(batch) >= 500:
                got += mr.put(batch)
                batch = []
            if i % 500 == 0:
                log(f'  {i:,}/{len(todo):,}')
    got += mr.put(batch)
    gone = [c for c in (_cve(r[0]) for r in _csv(session, 'deletions.csv')) if c in have]
    removed = mr.delete(gone)
    return {'fetched': got, 'removed': removed, 'documents': mr.count()}
