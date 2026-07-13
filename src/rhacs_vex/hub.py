"""hub.py — VEX repository ("vexhub") builder.

Assembles per-image OpenVEX documents into the aquasecurity/vex-repo-spec
layout that trivy consumes natively (`--vex repo`) and grype consumes as
plain files (`--vex <path>`, the path being derivable from the image ref):

    <hub>/
      vex-repository.json                     repository manifest
      .well-known/vex-repository.json         copy served for HTTPS discovery
      index.json                              purl → document location
      pkg/oci/<registry>/<ns>/<name>/scan.openvex.json

Split of concerns proven in docs/OPENVEX-SPIKE-RESULTS.md: the index `id`
carries the `repository_url` qualifier (trivy routing; grype never reads the
index) while the statement product @id inside each document stays a bare
digest-pinned purl (the only form both scanners match).

Documents are append-only per image *name*: each new release digest adds
statements; existing (CVE, product) pairs are replaced in place so re-runs
are idempotent.
"""
from __future__ import annotations

import json
import os
import zipfile
from datetime import datetime, timezone
from urllib.parse import quote

from . import openvex

DOC_BASENAME = 'scan.openvex.json'


def doc_path(hub_dir: str, image_ref: str) -> str:
    """pkg/oci/<registry>/<ns>/<name>/scan.openvex.json for an image ref."""
    return os.path.join(hub_dir, 'pkg', 'oci',
                        *openvex.repository_path(image_ref).split('/'),
                        DOC_BASENAME)


def _statement_key(stmt: dict):
    prods = stmt.get('products') or [{}]
    return (stmt.get('vulnerability', {}).get('name', ''),
            prods[0].get('@id', ''), stmt.get('status', ''))


def write_image_doc(hub_dir: str, image_ref: str, statements: list, *,
                    author: str, replace_digests: list = None) -> tuple:
    """Merge statements into the image's hub document.

    Returns (path, changed).  Statements are keyed by (CVE, product @id,
    status): same key → replaced (idempotent re-runs), new key → appended
    (new digest / new CVE).  The doc version bumps only on real change.

    Retraction: a re-scan of a digest is the complete truth for that digest —
    existing statements about it that the new set no longer carries are
    removed (verdicts age as Red Hat VEX updates; without this a stale
    suppression would live in the doc forever).  replace_digests widens the
    retraction set for batch callers merging several refs into one doc.
    """
    path = doc_path(hub_dir, image_ref)
    os.makedirs(os.path.dirname(path), exist_ok=True)

    existing = None
    if os.path.exists(path):
        try:
            with open(path) as fh:
                existing = json.load(fh)
        except Exception:
            existing = None

    def _canon(stmts):
        return sorted(json.dumps(s, sort_keys=True) for s in stmts)

    if existing:
        merged = {_statement_key(s): s for s in existing.get('statements', [])}
        before = _canon(merged.values())
        digs = {d for d in (replace_digests or [image_ref.split('@')[-1]])
                if str(d).startswith('sha256:')}
        new_keys = {_statement_key(s) for s in statements}
        def _about_rescanned(s):
            return any(d in p.get('@id', '') for p in s.get('products', [])
                       for d in digs)
        merged = {k: s for k, s in merged.items()
                  if k in new_keys or not _about_rescanned(s)}
        for s in statements:
            merged[_statement_key(s)] = s
        new_statements = [merged[k] for k in sorted(merged.keys())]
        changed = _canon(new_statements) != before
        if not changed:
            return path, False
        doc = openvex.build_document(
            image_ref, new_statements, author=author,
            doc_version=int(existing.get('version', 1)) + 1)
    else:
        if not statements:
            return path, False
        ordered = sorted(statements, key=_statement_key)
        doc = openvex.build_document(image_ref, ordered, author=author)

    with open(path, 'w') as fh:
        json.dump(doc, fh, indent=2)
        fh.write('\n')
    return path, True


def write_image_docs(hub_dir: str, per_image: dict, *, author: str) -> int:
    """Batch write_image_doc: {image_ref: statements} merged per document.

    Images sharing a name (e.g. every OCP release digest of ocp-v4.0-art-dev)
    land in one file — batching merges them in memory and writes each document
    once per run instead of once per digest.
    """
    by_path: dict = {}
    for image_ref, statements in per_image.items():
        by_path.setdefault(doc_path(hub_dir, image_ref), []).append(
            (image_ref, statements))
    changed_docs = 0
    for _path, group in by_path.items():
        first_ref = group[0][0]
        merged: list = []
        for _ref, statements in group:
            merged.extend(statements)
        digs = [ref.split('@')[-1] for ref, _ in group]
        _p, changed = write_image_doc(hub_dir, first_ref, merged, author=author,
                                      replace_digests=digs)
        changed_docs += bool(changed)
    return changed_docs


def prune(hub_dir: str, live_by_doc: dict) -> dict:
    """Drop statements about digests that rotated out of the discovery set.

    live_by_doc maps doc paths → the set of 'sha256:…' digests currently
    referenced by data/pullspecs/ + catalog channel heads.  Only documents in
    that map are touched: an image absent from discovery entirely (manually
    generated, unknown provenance) is preserved as-is.  A statement is dropped
    when every product digest it carries is dead; a document losing all
    statements is deleted.  Returns {'statements': n, 'docs_removed': n,
    'docs_updated': n}.
    """
    import re as _re
    from datetime import datetime, timezone

    stats = {'statements': 0, 'docs_removed': 0, 'docs_updated': 0}
    for path, live in live_by_doc.items():
        if not os.path.exists(path):
            continue
        try:
            with open(path) as fh:
                doc = json.load(fh)
        except Exception:
            continue

        def _digests(stmt):
            return {m.group(1)
                    for p in stmt.get('products', [])
                    for m in [_re.search(r'@(sha256:[a-f0-9]{64})',
                                         str(p.get('@id', '')))] if m}

        keep = []
        for s in doc.get('statements', []):
            digs = _digests(s)
            if digs and not (digs & live):
                stats['statements'] += 1
            else:
                keep.append(s)
        if len(keep) == len(doc.get('statements', [])):
            continue
        if keep:
            doc['statements'] = keep
            doc['version'] = int(doc.get('version', 1)) + 1
            doc['timestamp'] = datetime.now(timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%SZ')
            with open(path, 'w') as fh:
                json.dump(doc, fh, indent=2)
                fh.write('\n')
            stats['docs_updated'] += 1
        else:
            os.remove(path)
            stats['docs_removed'] += 1
            try:                       # clean now-empty directories
                os.removedirs(os.path.dirname(path))
            except OSError:
                pass
    return stats


def _index_entry(hub_dir: str, path: str) -> dict:
    """index.json entry from a document path — id derived from the layout.

    pkg/oci/<registry>/<ns...>/<name>/scan.openvex.json →
    id  = pkg:oci/<name>?repository_url=<registry%2Fns%2Fname>
    """
    rel = os.path.relpath(path, hub_dir)
    parts = rel.split(os.sep)
    repo_path = parts[2:-1]                     # strip pkg/oci/ … /scan.openvex.json
    name = repo_path[-1]
    return {
        'id': f"pkg:oci/{name}?repository_url={quote('/'.join(repo_path), safe='')}",
        'location': '/'.join(parts),
    }


def build_index(hub_dir: str, *, name: str, description: str,
                base_url: str = '', update_interval: str = '24h',
                archive: bool = False) -> dict:
    """(Re)write index.json + vex-repository.json from the documents on disk."""
    docs = []
    pkg_root = os.path.join(hub_dir, 'pkg')
    for root, _dirs, files in os.walk(pkg_root):
        for f in files:
            if f == DOC_BASENAME:
                docs.append(os.path.join(root, f))

    index = {
        'version': 1,
        'updated_at': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'packages': sorted((_index_entry(hub_dir, p) for p in docs),
                           key=lambda e: e['id']),
    }
    with open(os.path.join(hub_dir, 'index.json'), 'w') as fh:
        json.dump(index, fh, indent=2)
        fh.write('\n')

    manifest_path = os.path.join(hub_dir, 'vex-repository.json')
    if base_url:
        location = f"{base_url.rstrip('/')}/archive.zip"
    else:
        # Sticky: a previously published absolute location survives runs that
        # don't pass --base-url (generate's default) — otherwise every batch
        # run would clobber the manifest back to a relative path and break
        # trivy repo-mode consumers.
        location = 'archive.zip'
        try:
            with open(manifest_path) as fh:
                prev = json.load(fh)['versions'][0]['locations'][0]['url']
            if prev.startswith(('http://', 'https://')):
                location = prev
        except Exception:
            pass
    manifest = {
        'name': name,
        'description': description,
        'versions': [{
            'spec_version': '0.1',
            'locations': [{'url': location}],
            'update_interval': update_interval,
        }],
    }
    with open(os.path.join(hub_dir, 'vex-repository.json'), 'w') as fh:
        json.dump(manifest, fh, indent=2)
        fh.write('\n')
    os.makedirs(os.path.join(hub_dir, '.well-known'), exist_ok=True)
    with open(os.path.join(hub_dir, '.well-known', 'vex-repository.json'), 'w') as fh:
        json.dump(manifest, fh, indent=2)
        fh.write('\n')

    # Sticky like the location: once an archive exists, keep it current on
    # every reindex — a stale archive silently serves old verdicts to trivy.
    zpath = os.path.join(hub_dir, 'archive.zip')
    if archive or os.path.exists(zpath):
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(os.path.join(hub_dir, 'index.json'), 'index.json')
            for p in docs:
                z.write(p, os.path.relpath(p, hub_dir))

    return {'documents': len(docs), 'packages': len(index['packages'])}
