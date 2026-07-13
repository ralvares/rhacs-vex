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
                    author: str) -> tuple:
    """Merge statements into the image's hub document.

    Returns (path, changed).  Statements are keyed by (CVE, product @id,
    status): same key → replaced (idempotent re-runs), new key → appended
    (new digest / new CVE).  The doc version bumps only on real change.
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
        _p, changed = write_image_doc(hub_dir, first_ref, merged, author=author)
        changed_docs += bool(changed)
    return changed_docs


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

    location = f"{base_url.rstrip('/')}/archive.zip" if base_url else 'archive.zip'
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

    if archive:
        zpath = os.path.join(hub_dir, 'archive.zip')
        with zipfile.ZipFile(zpath, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(os.path.join(hub_dir, 'index.json'), 'index.json')
            for p in docs:
                z.write(p, os.path.relpath(p, hub_dir))

    return {'documents': len(docs), 'packages': len(index['packages'])}
