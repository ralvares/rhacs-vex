#!/usr/bin/env python3
"""Pack an evidence/ directory into zstd Parquet tables, losing nothing.

    python3 tests/pack_evidence.py [evidence] [evidence.parquet.tar]   # pack, then check a round trip
    python3 tests/pack_evidence.py --unpack evidence.parquet.tar <dir>   # original files back

Every JSON document is kept field for field (a `raw` column holds the full
object), only stored once: grype repeats each package and the SBOM source in
every match and in every run, so packages go to their own tables and matches
point at them by id.  Rows that repeat across runs are sorted next to each
other so the compressor folds them.  The engine's per-finding verdicts
(`findings`, every column of the triage frame) are added when rhacs_vex and
its index are available.

Tables (one row per …):
  images          image dir: ref, SBOM source / distro / descriptor / schema
  sbom_artifacts  SBOM package (full syft artifact; rpm file lists moved out)
  sbom_rpm_files  file of an rpm package, in columns (metadata.files[] entry)
  sbom_extra      SBOM files[] and artifactRelationships[] entries
  grype_artifacts package as grype reported it
  grype_matches   match or ignored match, per run (plain, vex, vex.stated);
                  raw without artifact / vulnerability (joined by art_key, vuln_key)
  grype_vulns     distinct grype vulnerability record
  grype_docs      run: source, distro, descriptor (DB build, config)
  openvex         statement, per document (inferred, stated)
  openvex_docs    document header
  findings        engine triage row
  files           every other file (logs, summaries, versions), as text
Read back: pandas.read_parquet('<table>.parquet'); json.loads(row.raw).  An
artifact whose raw has "_files_in_table" gets metadata.files back from
sbom_rpm_files (artifact id, ordered by idx).
"""
import hashlib
import json
import os
import sys
import tarfile
import tempfile

import pandas as pd

RUNS = {'grype.json': 'plain', 'grype.vex.json': 'vex', 'grype.vex.stated.json': 'vex.stated'}
FILE_KEYS = {'path', 'mode', 'size', 'digest', 'userName', 'groupName', 'flags'}
LISTS = ('matches', 'ignoredMatches')
DOCS = {'openvex.json': 'inferred', 'openvex.stated.json': 'stated'}


def _j(o) -> str:
    return json.dumps(o, sort_keys=True, separators=(',', ':'))


def _key(raw: str) -> str:
    return hashlib.sha1(raw.encode()).hexdigest()[:20]


def _load(p):
    try:
        with open(p) as fh:
            return json.load(fh)
    except (OSError, ValueError) as e:
        print(f'  unreadable {p}: {e}', file=sys.stderr)
        return None


def _split_files(img: str, a: dict, rows: list) -> dict:
    """rpm metadata.files[] → columnar rows (they are ~3/4 of an SBOM); the
    artifact keeps everything else.  Lists of any other shape stay in raw."""
    files = (a.get('metadata') or {}).get('files')
    if not files or not all(isinstance(f, dict) and set(f) <= FILE_KEYS
                            and set(f.get('digest') or {}) <= {'algorithm', 'value'} for f in files):
        return a
    for i, f in enumerate(files):
        dg = f.get('digest')
        rows.append({'image': img, 'artifact_id': a.get('id'), 'idx': i, 'path': f.get('path'),
                     'mode': f.get('mode'), 'size': f.get('size'),
                     'digest_algorithm': dg.get('algorithm') if dg is not None else None,
                     'digest': dg.get('value') if dg is not None else None,
                     'userName': f.get('userName'), 'groupName': f.get('groupName'), 'flags': f.get('flags'),
                     'keys': ','.join(k for k in f)})
    a = dict(a, metadata={k: v for k, v in a['metadata'].items() if k != 'files'})
    a['_files_in_table'] = len(files)
    return a


def _image_ref(name: str, sbom: dict) -> str:
    md = (sbom.get('source') or {}).get('metadata') or {}
    return md.get('userInput') or name


def _findings(img: str, ref: str, sbom_path: str, index):
    from rhacs_vex import vexgen
    from rhacs_vex.sbom import SyftSBOM
    sb = SyftSBOM.load(sbom_path)
    _stmts, df = vexgen.generate(ref, sb, index)
    df = df.copy()
    for c in df.columns:
        if df[c].dtype == object:
            df[c] = df[c].map(lambda v: v if v is None or isinstance(v, str) else _j(v) if isinstance(v, (list, dict)) else str(v))
    df.insert(0, 'image', img)
    return df


def pack(root: str) -> dict:
    T = {k: [] for k in ('images', 'sbom_artifacts', 'sbom_rpm_files', 'sbom_extra', 'grype_artifacts', 'grype_matches',
                         'grype_vulns', 'grype_docs', 'openvex', 'openvex_docs', 'files')}
    findings = []
    index = None
    try:
        from rhacs_vex import scanfree
        index = scanfree.load_index()
    except Exception as e:                      # noqa: BLE001 — findings are optional
        print(f'  no engine findings ({e})', file=sys.stderr)
    seen_ga, seen_gv = set(), set()
    for d, _dirs, names in sorted(os.walk(root)):
        img = os.path.relpath(d, root)
        for n in sorted(names):
            if n.startswith('._'):
                continue
            p = os.path.join(d, n)
            if n == 'sbom.syft.json':
                s = _load(p)
                if s is None:
                    continue
                ref = _image_ref(img, s)
                T['images'].append({'image': img, 'ref': ref, 'keys': _j(list(s)),
                                    **{k: _j(s.get(k)) for k in ('source', 'distro', 'descriptor', 'schema')}})
                for i, a in enumerate(s.get('artifacts') or []):
                    a = _split_files(img, a, T['sbom_rpm_files'])
                    T['sbom_artifacts'].append({'image': img, 'pos': i, 'id': a.get('id'), 'name': a.get('name'),
                                                'version': a.get('version'), 'type': a.get('type'),
                                                'purl': a.get('purl'), 'raw': _j(a)})
                for kind in ('files', 'artifactRelationships'):
                    for i, e in enumerate(s.get(kind) or []):
                        T['sbom_extra'].append({'image': img, 'kind': kind, 'pos': i, 'raw': _j(e)})
                if index is not None:
                    try:
                        findings.append(_findings(img, ref, p, index))
                    except Exception as e:      # noqa: BLE001
                        print(f'  findings failed for {img}: {e}', file=sys.stderr)
            elif n in RUNS:
                g = _load(p)
                if g is None:
                    continue
                run = RUNS[n]
                T['grype_docs'].append({'image': img, 'run': run, 'keys': _j(list(g)),
                                        'raw': _j({k: v for k, v in g.items() if k not in LISTS})})
                for lst in LISTS:
                    for i, m in enumerate(g.get(lst) or []):
                        m = dict(m)
                        a = m.pop('artifact', None)
                        araw = _j(a)
                        akey = _key(araw)
                        if (img, akey) not in seen_ga:
                            seen_ga.add((img, akey))
                            a = a or {}
                            T['grype_artifacts'].append({'image': img, 'art_key': akey, 'id': a.get('id'),
                                                         'name': a.get('name'), 'version': a.get('version'),
                                                         'type': a.get('type'), 'purl': a.get('purl'), 'raw': araw})
                        v = m.pop('vulnerability', None)
                        vraw = _j(v)
                        vkey = _key(vraw)
                        v = v or {}
                        if vkey not in seen_gv:
                            seen_gv.add(vkey)
                            T['grype_vulns'].append({'vuln_key': vkey, 'cve': v.get('id'),
                                                     'namespace': v.get('namespace'), 'raw': vraw})
                        a = json.loads(araw) or {}
                        T['grype_matches'].append({
                            'image': img, 'run': run, 'list': lst, 'pos': i, 'cve': v.get('id'),
                            'severity': v.get('severity'), 'pkg': a.get('name'), 'version': a.get('version'),
                            'type': a.get('type'), 'purl': a.get('purl'), 'artifact_id': a.get('id'),
                            'fix': _j((v.get('fix') or {}).get('versions') or []),
                            'ignored_by': _j(m.get('appliedIgnoreRules') or []),
                            'art_key': akey, 'vuln_key': vkey, 'raw': _j(m)})
            elif n in DOCS:
                o = _load(p)
                if o is None:
                    continue
                T['openvex_docs'].append({'image': img, 'doc': DOCS[n],
                                          'raw': _j({k: v for k, v in o.items() if k != 'statements'}),
                                          'has_statements': 'statements' in o})
                for i, st in enumerate(o.get('statements') or []):
                    T['openvex'].append({'image': img, 'doc': DOCS[n], 'pos': i,
                                         'cve': (st.get('vulnerability') or {}).get('name'),
                                         'status': st.get('status'), 'justification': st.get('justification'),
                                         'products': _j([x.get('@id') for x in st.get('products') or []]),
                                         'raw': _j(st)})
            else:
                try:
                    with open(p, errors='replace') as fh:
                        T['files'].append({'image': img, 'name': n, 'text': fh.read()})
                except OSError:
                    pass
    out = {k: pd.DataFrame(v) for k, v in T.items()}
    sort = {'grype_matches': ['image', 'cve', 'artifact_id', 'list', 'run'],
            'grype_artifacts': ['image', 'type', 'name', 'id'],
            'grype_vulns': ['cve', 'namespace'],
            'sbom_artifacts': ['image', 'type', 'name', 'id'],
            'openvex': ['image', 'cve', 'doc']}
    for k, cols in sort.items():
        if len(out[k]):
            out[k] = out[k].sort_values(cols, na_position='last', kind='stable').reset_index(drop=True)
    if findings:
        out['findings'] = pd.concat(findings, ignore_index=True)
    return out


def _read(src: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(src) as tar:
            tar.extractall(tmp, filter='data')
        base = os.path.join(tmp, 'evidence')
        return {f[:-8]: pd.read_parquet(os.path.join(base, f)) for f in os.listdir(base)}


def _rows(T: dict, name: str, img: str):
    df = T.get(name)
    return [] if df is None else df[df['image'] == img].to_dict('records')


def unpack(src: str, out: str) -> None:
    """Rebuild every original file from the tables (findings stay a table)."""
    T = _read(src)
    empty = pd.DataFrame()
    imgs = set()
    for df in T.values():
        if 'image' in df.columns:
            imgs.update(df['image'])
    files = {}
    for r in T.get('sbom_rpm_files', empty).to_dict('records'):
        full = {'path': r['path'], 'mode': r['mode'], 'size': r['size'],
                'digest': {'algorithm': r['digest_algorithm'], 'value': r['digest']},
                'userName': r['userName'], 'groupName': r['groupName'], 'flags': r['flags']}
        f = {k: _native(full[k]) for k in r['keys'].split(',') if k}
        files.setdefault((r['image'], r['artifact_id']), []).append((r['idx'], f))
    vulns = {r['vuln_key']: r['raw'] for r in T.get('grype_vulns', empty).to_dict('records')}
    for img in sorted(imgs):
        d = os.path.join(out, img)
        os.makedirs(d, exist_ok=True)
        for im in _rows(T, 'images', img):
            arts = []
            for r in sorted(_rows(T, 'sbom_artifacts', img), key=lambda r: r['pos']):
                art = json.loads(r['raw'])
                if art.pop('_files_in_table', None) is not None:
                    art['metadata']['files'] = [f for _i, f in sorted(files.get((img, art.get('id')), []),
                                                                       key=lambda x: x[0])]
                arts.append(art)
            extra = sorted(_rows(T, 'sbom_extra', img), key=lambda r: r['pos'])
            parts = {'artifacts': arts,
                     **{k: [json.loads(r['raw']) for r in extra if r['kind'] == k]
                        for k in ('files', 'artifactRelationships')},
                     **{k: json.loads(im[k]) for k in ('source', 'distro', 'descriptor', 'schema')}}
            _dump(os.path.join(d, 'sbom.syft.json'), {k: parts[k] for k in json.loads(im['keys'])})
        gart = {r['art_key']: r['raw'] for r in _rows(T, 'grype_artifacts', img)}
        for fname, run in RUNS.items():
            docs = [r for r in _rows(T, 'grype_docs', img) if r['run'] == run]
            if not docs:
                continue
            rest = json.loads(docs[0]['raw'])
            ms = [r for r in _rows(T, 'grype_matches', img) if r['run'] == run]
            lists = {}
            for lst in LISTS:
                lists[lst] = []
                for r in sorted((r for r in ms if r['list'] == lst), key=lambda r: r['pos']):
                    m = json.loads(r['raw'])
                    m['vulnerability'] = json.loads(vulns[r['vuln_key']])
                    m['artifact'] = json.loads(gart[r['art_key']])
                    lists[lst].append(m)
            g = {k: (lists[k] if k in LISTS else rest[k]) for k in json.loads(docs[0]['keys'])}
            _dump(os.path.join(d, fname), g)
        for fname, kind in DOCS.items():
            head = [r for r in _rows(T, 'openvex_docs', img) if r['doc'] == kind]
            if not head:
                continue
            o = json.loads(head[0]['raw'])
            if head[0]['has_statements']:
                st = sorted((r for r in _rows(T, 'openvex', img) if r['doc'] == kind), key=lambda r: r['pos'])
                o['statements'] = [json.loads(r['raw']) for r in st]
            _dump(os.path.join(d, fname), o)
        for r in _rows(T, 'files', img):
            with open(os.path.join(d, r['name']), 'w') as fh:
                fh.write(r['text'])


def _native(v):
    """numpy scalars from parquet → plain ints / None for json."""
    if v is None or isinstance(v, (str, dict)):
        return v
    if hasattr(v, 'item'):
        v = v.item()
    if isinstance(v, float):
        return None if v != v else int(v) if v.is_integer() else v
    return v


def _dump(p: str, o) -> None:
    with open(p, 'w') as fh:
        json.dump(o, fh)


def verify(root: str, tar: str) -> int:
    """Unpack `tar` and compare every file with `root`."""
    with tempfile.TemporaryDirectory() as tmp:
        unpack(tar, os.path.join(tmp, 'out'))
        bad = 0
        for d, _dirs, names in os.walk(root):
            for n in names:
                if n.startswith('._'):
                    continue
                a = os.path.join(d, n)
                b = os.path.join(tmp, 'out', os.path.relpath(a, root))
                if n.endswith('.json'):
                    same = os.path.exists(b) and _load(a) == _load(b)
                else:
                    same = os.path.exists(b) and open(a, 'rb').read() == open(b, 'rb').read()
                if not same:
                    bad += 1
                    print(f'  DIFFERS: {os.path.relpath(a, root)}')
        print('round trip: every file identical' if not bad else f'round trip: {bad} files differ')
        return 1 if bad else 0


def write(tables: dict, dest: str) -> None:
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(dest, 'w') as tar:
        for name, df in tables.items():
            if df.empty:
                continue
            p = os.path.join(tmp, f'{name}.parquet')
            df.to_parquet(p, compression='zstd', compression_level=19, index=False)
            tar.add(p, arcname=f'evidence/{name}.parquet')
            print(f'  {name:16s} {len(df):>8} rows  {os.path.getsize(p) / 1e6:7.1f} MB')
    print(f'{dest}: {os.path.getsize(dest) / 1e6:.1f} MB')


def main() -> int:
    a = sys.argv[1:]
    if a[:1] == ['--unpack']:
        unpack(a[1], a[2] if len(a) > 2 else 'evidence.unpacked')
        return 0
    root = a[0] if a else 'evidence'
    dest = a[1] if len(a) > 1 else 'evidence.parquet.tar'
    write(pack(root), dest)
    return verify(root, dest)


if __name__ == '__main__':
    sys.exit(main())
