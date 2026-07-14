"""grype adapter — syft SBOM generation + grype scan → triage DataFrame.

Flow (docs/OPENVEX-SPIKE-RESULTS.md): syft must emit **syft-json** (the SPDX
export drops repoDigests and grype then has no image identity to match VEX
products against); grype runs with --by-cve so GHSA aliases collapse onto the
CVE ids the Red Hat VEX files are keyed by.
"""
from __future__ import annotations

import json
import os
import re
import subprocess

import pandas as pd

SYFT_DIR = os.path.join('data', 'syft')

# grype artifact type → the SOURCE vocabulary the engine already knows from
# RHACS scans (GO/OS/PYTHON/...).  Unknown types stay unmapped and their rows
# are still triaged; they just mint no subcomponent purl on export.
_TYPE_TO_SOURCE = {
    'rpm':          'OS',
    'go-module':    'GO',
    'python':       'PYTHON',
    'npm':          'NODEJS',
    'java-archive': 'JAVA',
}

_SEVERITY = {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
             'low': 'LOW', 'negligible': 'LOW'}


def _run(cmd: list, what: str) -> subprocess.CompletedProcess:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        tail = (proc.stderr or '').strip().splitlines()[-3:]
        raise RuntimeError(f"{what} failed ({proc.returncode}): " + ' / '.join(tail))
    return proc


def syft_sbom(image_ref: str, *, platform: str = 'linux/amd64',
              force: bool = False) -> str:
    """Generate (or reuse) the syft-json SBOM for an image ref; returns path."""
    os.makedirs(SYFT_DIR, exist_ok=True)
    path = os.path.join(SYFT_DIR, image_ref.replace('/', '_') + '.json')
    if not force and os.path.exists(path) and os.path.getsize(path) > 0:
        return path
    _run(['syft', f'registry:{image_ref}', '--platform', platform,
          '-o', f'syft-json={path}'], 'syft')
    return path


_GRYPE_DIR = os.path.join('data', 'scans', 'grype')
_DB_STAMP: list = []          # memo — one `grype db status` per process


def _grype_db_stamp() -> str:
    """Identity of the current grype DB (built timestamp), '' if unknown.

    Cache-key component: an SBOM is immutable (digest-pinned image), so a
    grype result is valid exactly as long as the DB it was produced with.
    """
    if not _DB_STAMP:
        stamp = ''
        try:
            proc = subprocess.run(['grype', 'db', 'status', '-o', 'json'],
                                  capture_output=True, text=True, timeout=15)
            built = str(json.loads(proc.stdout).get('built', ''))
            stamp = re.sub(r'[^0-9TZ]', '', built)
        except Exception:
            pass
        _DB_STAMP.append(stamp)
    return _DB_STAMP[0]


def grype_scan(target: str) -> dict:
    """Run grype (CVE-normalized ids) on an SBOM path or image ref.

    SBOM scans are cached per (SBOM, DB build): the SBOM never changes, so a
    re-run against the same vulnerability DB returns the identical report —
    cache-hot batch re-runs skip grype entirely.  A new DB build invalidates
    naturally (new stamp in the filename); stale stamps are cleaned as they
    are superseded.
    """
    src = f'sbom:{target}' if os.path.exists(target) else f'registry:{target}'
    cpath = None
    if src.startswith('sbom:'):
        stamp = _grype_db_stamp()
        if stamp:
            base = os.path.basename(target)
            cpath = os.path.join(_GRYPE_DIR, f'{base}.{stamp}.grype.json')
            if os.path.exists(cpath) and os.path.getsize(cpath) > 0:
                try:
                    with open(cpath) as fh:
                        return json.load(fh)
                except Exception:
                    pass
    proc = _run(['grype', src, '--by-cve', '-o', 'json'], 'grype')
    doc = json.loads(proc.stdout)
    if cpath:
        os.makedirs(_GRYPE_DIR, exist_ok=True)
        import glob as _glob
        import tempfile as _tempfile
        for old in _glob.glob(os.path.join(
                _GRYPE_DIR, os.path.basename(target) + '.*.grype.json')):
            try:
                os.remove(old)
            except OSError:
                pass
        fd, tmp = _tempfile.mkstemp(dir=_GRYPE_DIR, suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as fh:
                json.dump(doc, fh)
            os.replace(tmp, cpath)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return doc


def rpm_file_owners(sbom_path: str) -> dict:
    """path → ('rpm name', 'version-release') for every rpm-owned file.

    Bridges the identity gap for go binaries shipped inside rpms: the scanner
    reports the golang module (pkg:golang/golang.org/x/net@…), while Red Hat
    assesses the VENDORING rpm (rhel9:buildah).  File ownership from the SBOM
    is the structural link between the two.
    """
    try:
        with open(sbom_path) as fh:
            doc = json.load(fh)
    except Exception:
        return {}
    owners = {}
    for a in doc.get('artifacts', []):
        if a.get('type') != 'rpm':
            continue
        name = a.get('name', '')
        ver = re.sub(r'^\d+:', '', str(a.get('version', '')))
        if not name or not ver:
            continue
        for f in (a.get('metadata') or {}).get('files') or []:
            path = f.get('path') if isinstance(f, dict) else str(f)
            if path:
                owners[path] = (name, ver)
    return owners


def fallback_platform(image_ref: str) -> str:
    """First linux platform in the image's manifest index, '' if none.

    For single-arch-family images (e.g. OpenJ9 builds ship only ppc64le and
    s390x) the requested platform may not exist at all — the digest-pinned
    statements are equally valid for whichever build the index does carry.
    """
    try:
        out = subprocess.run(
            ['skopeo', 'inspect', '--raw', f'docker://{image_ref}'],
            capture_output=True, text=True, timeout=60)
        for m in json.loads(out.stdout).get('manifests', []):
            p = m.get('platform', {})
            if p.get('os') == 'linux' and p.get('architecture'):
                return f"linux/{p['architecture']}"
    except Exception:
        pass
    return ''


def sbom_labels(sbom_path: str) -> dict:
    """Image labels recorded in the syft-json SBOM (source.metadata.labels).

    Saves a skopeo inspect per image — the SBOM already carries the OCI config.
    {} when absent (e.g. scratch images), letting callers fall back.
    """
    try:
        with open(sbom_path) as fh:
            doc = json.load(fh)
        return (doc.get('source', {}).get('metadata') or {}).get('labels') or {}
    except Exception:
        return {}


def sbom_digests(sbom_path: str) -> list:
    """sha256 identities of the scanned build from the syft-json SBOM.

    manifestDigest is the PLATFORM manifest digest — the identity Red Hat VEX
    product ids carry (per-arch), unlike the multi-arch list digest in the
    pull ref.  repoDigests included for completeness.
    """
    try:
        with open(sbom_path) as fh:
            md = json.load(fh).get('source', {}).get('metadata') or {}
        out = [md.get('manifestDigest') or '']
        out += list(md.get('repoDigests') or [])
        return [d for d in out if d]
    except Exception:
        return []


def to_df(grype_doc: dict) -> pd.DataFrame:
    """Flatten grype matches into the triage DataFrame shape (rhacs_to_df)."""
    rows, seen = [], set()
    for m in grype_doc.get('matches', []):
        vuln, art = m.get('vulnerability', {}), m.get('artifact', {})
        cve = str(vuln.get('id', '')).upper().strip()
        if not cve.startswith('CVE-'):
            continue
        cname, cver = art.get('name', ''), art.get('version', '')
        key = (cname, cver, cve)
        if key in seen:
            continue
        seen.add(key)
        locations = art.get('locations') or [{}]
        fix = (vuln.get('fix') or {}).get('versions') or []
        # source-rpm name from the purl's upstream qualifier — Red Hat verdicts
        # are per source package, so the emitter extends rpm statements to it.
        srpm = ''
        m_up = re.search(r'upstream=([^&]+?)-[^-]+-[^-]+\.src\.rpm', art.get('purl', ''))
        if m_up:
            srpm = m_up.group(1)
        rows.append({
            'COMPONENT':     cname,
            'VERSION':       cver,
            'CVE':           cve,
            'SEVERITY':      _SEVERITY.get(str(vuln.get('severity', '')).lower(), ''),
            'CVSS':          0,
            'LINK':          vuln.get('dataSource', ''),
            'FIXED_VERSION': fix[0] if fix else '',
            'SOURCE':        _TYPE_TO_SOURCE.get(art.get('type', ''), ''),
            'LOCATION':      locations[0].get('path', ''),
            'ADVISORY':      '',
            'ADVISORY_LINK': '',
            'SRPM':          srpm,
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK',
                 'FIXED_VERSION', 'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK'])


def os_hint(grype_doc: dict) -> str:
    """Distro string from the grype document (refines ctx.rhel_ver)."""
    d = grype_doc.get('distro') or {}
    return f"{d.get('name', '')}:{d.get('version', '')}"
