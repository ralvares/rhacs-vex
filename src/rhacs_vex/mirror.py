"""The local mirror of Red Hat's CSAF-VEX corpus (data/vex/CVE-*.json).

The only module that fetches VEX from Red Hat.  A triage run answers from the
mirror, full stop: `ensure_mirror` syncs it once up front when it is older than
a day, and nothing fetches mid-audit, so no verdict depends on which files some
earlier run happened to pull.

    changes.csv          every VEX file with its last-change time → mirror by
                         difference (missing + changed)
    archive_latest.txt   dated .tar.zst of the whole corpus → used when more
                         than VEX_BULK_THRESHOLD files are outstanding
    ETag sidecar         conditional GETs for the per-file path
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from .core.store import VEX_DIR, vex_path

VEX_FEED = 'https://security.access.redhat.com/data/csaf/v2/vex'
CHANGES_URL = f'{VEX_FEED}/changes.csv'
ARCHIVE_PTR = f'{VEX_FEED}/archive_latest.txt'

SYNC_STAMP = os.path.join(VEX_DIR, '.sync.json')
MIRROR_MAX_AGE = int(os.environ.get('VEX_MAX_AGE', 24 * 3600))
BULK_THRESHOLD = int(os.environ.get('VEX_BULK_THRESHOLD', '2000'))
WORKERS = 20

_ETAG_PATH = os.path.join(VEX_DIR, '.etags.json')
_ETAG_LOCK = threading.Lock()
_etags: dict | None = None


# ── freshness ────────────────────────────────────────────────────────────────

def mirror_age():
    """Seconds since the mirror last synced completely, or None if never."""
    try:
        with open(SYNC_STAMP) as fh:
            return max(0.0, time.time() - float(json.load(fh)['at']))
    except Exception:
        return None


def ensure_mirror(console=None, skip: bool = False, max_age: int = 0) -> None:
    """Sync when the mirror is missing or stale; otherwise do nothing.

    Call once, before any worker pool — a sync started inside a pool would have
    every thread pulling the same archive.  VEX_SKIP_SYNC / VEX_OFFLINE disable it.
    """
    if skip or os.environ.get('VEX_SKIP_SYNC') or os.environ.get('VEX_OFFLINE'):
        return
    age = mirror_age()
    if age is not None and age < (max_age or MIRROR_MAX_AGE):
        return
    if console:
        console.print("🔄 VEX mirror " + (f"is {age / 3600:.0f}h old" if age is not None
                                          else "has never synced") + " — syncing")
    try:
        sync(console)
    except RuntimeError as e:
        if console:
            console.print(f'[yellow]sync skipped ({e}) — using the mirror as it is[/yellow]')


# ── sync ─────────────────────────────────────────────────────────────────────

def sync(console=None, workers: int = 0, limit: int = 0, bulk=None) -> dict:
    """Bring data/vex level with Red Hat's published corpus.

    Fetches what is missing and what changed since the local copy was written.
    The sync stamp is written only when nothing is left outstanding — marking a
    short mirror current would make every absent CVE read as "no VEX file".
    """
    try:
        res = requests.get(CHANGES_URL, timeout=60)
        res.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f'could not read the change feed: {e}') from e

    want = {}
    for line in res.text.splitlines():
        parts = [p.strip().strip('"') for p in line.split('","')]
        if len(parts) == 2 and parts[0].endswith('.json'):
            cve = os.path.basename(parts[0])[:-5].upper()
            if cve.startswith('CVE-'):
                want[cve] = parts[1]

    os.makedirs(VEX_DIR, exist_ok=True)
    missing = [c for c in want if not os.path.exists(vex_path(c))]
    absent = set(missing)
    stale = [c for c in want if c not in absent and _outdated(c, want[c])]
    todo = (missing + stale)[:limit] if limit else missing + stale
    if console:
        console.print(f"📚 corpus {len(want):,} CVEs · local {len(want) - len(missing):,} · "
                      f"missing {len(missing):,} · changed {len(stale):,}")

    fetched, used_bulk, updated = 0, False, list(todo)
    if todo:
        if bulk is None:
            bulk = not limit and len(todo) > BULK_THRESHOLD
        if bulk:
            try:
                fetched = _bulk_fetch(console)
                used_bulk = True
                # the archive is cut on a date; fetch what changed after it
                todo = [c for c in todo if _outdated(c, want[c])]
                if todo and console:
                    console.print(f"🔄 {len(todo):,} changed since the archive was cut")
            except RuntimeError as e:
                if console:
                    console.print(f'[yellow]bulk archive skipped ({e}) — fetching file '
                                  f'by file[/yellow]')
        fetched += _fetch_many(todo, workers or WORKERS, console)

    left = [c for c in want if _outdated(c, want[c])]
    if not left:
        try:
            with open(SYNC_STAMP, 'w') as fh:
                json.dump({'at': time.time(), 'corpus': len(want), 'fetched': fetched}, fh)
        except OSError:
            pass
    elif console:
        console.print(f"[yellow]{len(left):,} file(s) still missing — the mirror "
                      f"is not marked current[/yellow]")
    # `updated` lets the index re-read just these files; after a bulk archive
    # unpack every file may have changed, so it is None (rebuild everything).
    return {'corpus': len(want), 'missing': len(missing), 'changed': len(stale),
            'fetched': fetched, 'outstanding': len(left),
            'updated': None if used_bulk else updated}


def _outdated(cve: str, stamp: str) -> bool:
    """Absent locally, or older than Red Hat's last change."""
    try:
        return os.path.getmtime(vex_path(cve)) < datetime.fromisoformat(stamp).timestamp()
    except (OSError, ValueError):
        return True


def _fetch_many(cves, workers, console) -> int:
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in as_completed([ex.submit(fetch, c) for c in cves]):
            done += 1
            if console and done % 500 == 0:
                console.print(f"   {done:,}/{len(cves):,}", highlight=False)
    return len(cves)


def fetch(cve_id: str) -> bool:
    """Download one VEX file (conditional on its ETag).  True when on disk after."""
    cve_id = cve_id.upper().strip()
    m = re.search(r'CVE-(\d{4})-', cve_id)
    if not m:
        return False
    url = f"{VEX_FEED}/{m.group(1)}/{cve_id.lower()}.json"
    path = vex_path(cve_id)
    headers = {}
    etag = _etag(cve_id) if os.path.exists(path) else ''
    if etag:
        headers['If-None-Match'] = etag
    try:
        res = requests.get(url, timeout=10, headers=headers)
    except requests.RequestException:
        return os.path.exists(path)
    if res.status_code == 304:
        os.utime(path, None)
        return True
    if res.status_code != 200:
        return os.path.exists(path)
    _atomic_write(path, res.text)
    if res.headers.get('ETag'):
        _set_etag(cve_id, res.headers['ETag'])
    return True


def _bulk_fetch(console, chunk=1 << 20) -> int:
    """Unpack Red Hat's dated corpus archive straight into the mirror layout.

    273 MB against ~49,000 HTTPS round trips.  Raises RuntimeError when the
    archive or `zstd` is unavailable so the caller can fall back.
    """
    if not shutil.which('zstd'):
        raise RuntimeError('zstd is not installed')
    try:
        name = requests.get(ARCHIVE_PTR, timeout=30).text.strip().splitlines()[0]
        res = requests.get(f'{VEX_FEED}/{name}', timeout=120, stream=True)
        res.raise_for_status()
    except (requests.RequestException, IndexError) as e:
        raise RuntimeError(f'archive unavailable: {e}') from e

    total = int(res.headers.get('Content-Length') or 0)
    if console:
        console.print(f"📦 {name} ({total / 1e6:.0f} MB)")
    fd, archive = tempfile.mkstemp(dir=VEX_DIR, suffix='.tar.zst')
    written = 0
    try:
        with os.fdopen(fd, 'wb') as fh:
            got = 0
            for blk in res.iter_content(chunk_size=chunk):
                fh.write(blk)
                got += len(blk)
                if console and total and got % (50 << 20) < chunk:
                    console.print(f"   {got / 1e6:.0f}/{total / 1e6:.0f} MB", highlight=False)
        proc = subprocess.Popen(['zstd', '-dc', archive], stdout=subprocess.PIPE)
        try:
            with tarfile.open(fileobj=proc.stdout, mode='r|') as tf:
                for member in tf:
                    base = os.path.basename(member.name)
                    cve = base[:-5].upper()
                    if not (member.isfile() and base.lower().endswith('.json')
                            and cve.startswith('CVE-')):
                        continue
                    src = tf.extractfile(member)
                    if src is None:
                        continue
                    part = os.path.join(VEX_DIR, f'.{cve}.part')
                    with open(part, 'wb') as out:
                        shutil.copyfileobj(src, out, chunk)
                    os.replace(part, vex_path(cve))
                    written += 1
                    if console and written % 5000 == 0:
                        console.print(f"   unpacked {written:,}", highlight=False)
        finally:
            if proc.stdout:
                proc.stdout.close()
            proc.wait()
    finally:
        try:
            os.unlink(archive)
        except OSError:
            pass
    return written


# ── ETag sidecar ─────────────────────────────────────────────────────────────

def _etag(cve_id: str) -> str:
    global _etags
    with _ETAG_LOCK:
        if _etags is None:
            try:
                with open(_ETAG_PATH) as fh:
                    _etags = json.load(fh)
            except Exception:
                _etags = {}
        return _etags.get(cve_id, '')


def _set_etag(cve_id: str, etag: str) -> None:
    _etag(cve_id)                       # make sure the sidecar is loaded
    with _ETAG_LOCK:
        _etags[cve_id] = etag
        _atomic_write(_ETAG_PATH, json.dumps(_etags))


def _atomic_write(path: str, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix='.tmp')
    try:
        with os.fdopen(fd, 'w') as fh:
            fh.write(text)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
