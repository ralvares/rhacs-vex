"""report.py — triage a RHACS vulnerability report CSV into one shareable HTML.

`triage.html` does this in the browser: you upload the CSV, it fetches the
per-version parquets and joins them by image digest.  That needs the parquets to
exist and to cover the versions in front of you.  This module answers the same
question without them — the CSV says what is deployed where, the engine says
what each finding is worth, and the result is a single self-contained file you
can send to someone who has neither this repo nor a cluster.

Three things the CSV does not carry, and where each comes from:

* **installed versions** — the report names the package, never its NEVRA, and
  §6b cannot compare what it cannot see.  syft reads them from the image itself
  (SBOMs cache under data/syft, so a second run is free).
* **errata rows** — 2,001 of 5,200 rows on the reference report carry an
  `RHSA-…` id where the CVE should be.  Red Hat's CSAF advisory document lists
  the CVEs each erratum fixes, so one fetch per advisory expands them.
* **OpenShift version** — nowhere in the CSV.  It is on the image, in the
  `version` label, which the same syft run already reads.

The middle of the pipeline runs in two phases, and the split is deliberate.
Scanning is subprocesses and registry traffic, one image at a time and
independent, so it fans out across `--workers`.  Judging is pure Python holding
Red Hat's VEX corpus, where a thread pool buys nothing (the GIL) and costs the
resident corpus once per worker — so it runs single-threaded, over the distinct
findings rather than the reported rows, walking CVE by CVE so each VEX document
is read once for the whole report and freed before the next.
"""
from __future__ import annotations

import functools
import json
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests

ADVISORY_FEED = 'https://security.access.redhat.com/data/csaf/v2/advisories'

# The column names triage.html maps, so one CSV feeds both paths.
COLUMNS = {'cluster': 'Cluster', 'namespace': 'Namespace', 'deployment': 'Deployment',
           'image': 'Image', 'component': 'Component', 'cve': 'CVE',
           'fixable': 'Fixable', 'fixed_in': 'CVE Fixed In', 'severity': 'Severity',
           'cvss': 'CVSS', 'advisory': 'Advisory Name', 'link': 'Advisory Link'}

_ERRATUM = re.compile(r'^(RH[SBE]A)-(\d{4}):(\d+)$', re.I)


def digest_key(image_ref: str) -> str:
    """What identifies a build: its digest, or the whole ref when unpinned."""
    m = re.search(r'@(sha256:[0-9a-f]+)', str(image_ref or ''))
    return m.group(1) if m else str(image_ref or '')


def read_report(path: str) -> pd.DataFrame:
    """Load a RHACS report CSV, whichever delimiter the export used."""
    with open(path, encoding='utf-8-sig', errors='replace') as fh:
        head = fh.readline()
    sep = ';' if head.count(';') > head.count(',') else ','
    df = pd.read_csv(path, sep=sep, dtype=str, encoding='utf-8-sig',
                     keep_default_na=False).rename(columns=lambda c: c.strip())
    missing = [c for c in ('Cluster', 'Image', 'Component', 'CVE') if c not in df.columns]
    if missing:
        raise ValueError(f'not a RHACS vulnerability report — missing {", ".join(missing)}')
    return df


@functools.lru_cache(maxsize=4096)
def erratum_cves(advisory_id: str) -> tuple:
    """CVEs an RHSA/RHBA/RHEA fixes, from its CSAF document.  Memory only."""
    m = _ERRATUM.match(str(advisory_id or '').strip())
    if not m:
        return ()
    kind, year, num = m.group(1).lower(), m.group(2), m.group(3)
    url = f'{ADVISORY_FEED}/{year}/{kind}-{year}_{num}.json'
    try:
        res = requests.get(url, timeout=20)
        if res.status_code != 200:
            return ()
        doc = json.loads(res.text, strict=False)
    except Exception:
        return ()
    return tuple(v['cve'] for v in doc.get('vulnerabilities') or [] if v.get('cve'))


def expand_errata(df: pd.DataFrame, workers: int = 8, progress=None) -> pd.DataFrame:
    """Replace each erratum row with one row per CVE that erratum fixes.

    RHACS reports a fixable finding under the erratum that fixes it, which is the
    right thing for patching and the wrong thing for VEX lookup.  The erratum id
    is kept in ADVISORY so the row still points at what to apply.
    """
    ids = sorted({c for c in df['CVE'].unique() if _ERRATUM.match(str(c))})
    if not ids:
        return df
    with ThreadPoolExecutor(max_workers=workers) as ex:
        mapped = dict(zip(ids, ex.map(erratum_cves, ids)))
    if progress:
        hit = sum(1 for v in mapped.values() if v)
        progress(f'{hit}/{len(ids)} errata expanded to '
                 f'{sum(len(v) for v in mapped.values())} CVEs')
    rows = []
    for rec in df.to_dict('records'):
        cves = mapped.get(rec['CVE'])
        if not cves:
            rows.append(rec)
            continue
        for cve in cves:
            rows.append({**rec, 'CVE': cve, 'ADVISORY': rec['CVE']})
    return pd.DataFrame(rows).fillna('')


def _sbom_index(sbom_path: str) -> dict:
    """{package name: (version, source, location)} from a syft SBOM."""
    try:
        doc = json.load(open(sbom_path))
    except Exception:
        return {}
    kind = {'rpm': ('OS', 'var/lib/rpm'), 'go-module': ('GO', ''),
            'python': ('PYTHON', ''), 'npm': ('NODEJS', ''), 'java-archive': ('JAVA', '')}
    out = {}
    for art in doc.get('artifacts') or []:
        name, ver = art.get('name'), art.get('version')
        if not (name and ver) or name in out:
            continue
        src, loc = kind.get(art.get('type'), ('OS', ''))
        locs = art.get('locations') or []
        out[name] = (ver, src, loc or (locs[0].get('path', '') if locs else ''))
    return out


def image_facts(image_ref: str, platform: str = 'linux/amd64') -> dict:
    """SBOM-derived versions, labels and digests for one image.

    Failure is expected and survivable: an image the registry will not serve
    still has report rows, they just carry no installed version.
    """
    from .adapters import grype as adapter
    facts = {'ref': image_ref, 'packages': {}, 'labels': {}, 'digests': [], 'error': ''}
    try:
        sbom = adapter.syft_sbom(image_ref, platform=platform)
    except Exception as e:
        facts['error'] = f'{type(e).__name__}: {str(e)[:120]}'
        return facts
    facts['packages'] = _sbom_index(sbom)
    facts['labels'] = adapter.sbom_labels(sbom) or {}
    facts['digests'] = adapter.sbom_digests(sbom) or []
    return facts


def ocp_version(labels: dict) -> str:
    """OpenShift version from `io.openshift.release`, or '' — never a guess.

    An image's own `version` label is its build's version, whatever product that
    build belongs to, and nothing in the label set separates a release-payload
    image from an operator that also stamps `vX.Y.Z`.  Measured across 2,595
    cached SBOMs: v4.x covers 972 images, v2.x 533, v3.x 597, v1.x 399 — and
    every one of those groups carries the same distinctive Red Hat labels
    (`com.redhat.component`, `io.openshift.expose-services`, `io.openshift.tags`).
    Reading `version` as an OpenShift version put "OpenShift 2.17.0" against 45
    images of the reference report.

    The cluster's version is a property of the cluster, not of an image pulled
    into it, so `--ocp` states it and this returns what the build itself claims
    only when the build claims it outright.
    """
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)',
                  str((labels or {}).get('io.openshift.release') or ''))
    return m.group(1) if m else ''


# Every CSV column the pipeline below actually reads — rows_for_image's inputs,
# the placement keys, and ADVISORY, which expand_errata writes.
_CARRIED = ('Cluster', 'Namespace', 'Deployment', 'Image', 'Component', 'CVE',
            'Severity', 'CVSS', 'Reference', 'CVE Fixed In', 'Fixable',
            'Advisory Name', 'Advisory Link', 'ADVISORY')


def rows_for_image(report_rows, facts: dict) -> pd.DataFrame:
    """Triage-shaped rows for one image, versions filled in from its SBOM.

    A component the SBOM does not name gets no SOURCE at all.  Defaulting it to
    OS would route a Java finding down the RPM ladder — RHACS names those
    `group:artifact` (`com.fasterxml.jackson.core:jackson-core`) while syft names
    the artifact alone, so the miss is routine, not an edge case.  The engine
    reads an absent `.elN` marker as non-RPM, which is the right ladder for
    anything that is not an rpm.
    """
    pkgs = facts.get('packages') or {}
    out = []
    for rec in report_rows:
        comp = str(rec.get('Component') or '').strip()
        # Maven coordinates: the artifact is what syft and the VEX both name.
        alt = comp.rsplit(':', 1)[-1] if ':' in comp and '/' not in comp else ''
        ver, source, loc = pkgs.get(comp) or pkgs.get(alt) or ('', '', '')
        out.append({
            'COMPONENT': comp, 'VERSION': ver, 'CVE': str(rec.get('CVE') or '').strip(),
            'SEVERITY': str(rec.get('Severity') or ''), 'CVSS': rec.get('CVSS') or 0,
            'LINK': str(rec.get('Reference') or ''), 'SOURCE': source, 'LOCATION': loc,
            'FIXED_VERSION': str(rec.get('CVE Fixed In') or ''),
            'ADVISORY': str(rec.get('ADVISORY') or rec.get('Advisory Name') or ''),
            'ADVISORY_LINK': str(rec.get('Advisory Link') or ''),
            'CLUSTER': str(rec.get('Cluster') or ''),
            'NAMESPACE': str(rec.get('Namespace') or ''),
            'DEPLOYMENT': str(rec.get('Deployment') or ''),
            'IMAGE': str(rec.get('Image') or ''),
            'FIXABLE': str(rec.get('Fixable') or ''),
        })
    return pd.DataFrame(out)


# The only columns that vary between two report rows describing the same
# finding.  The engine reads none of them (COMPONENT, VERSION, CVE, SOURCE,
# SRPM, SEVERITY, FIXED_VERSION are the whole of its input), so collapsing on
# everything else cannot change a verdict.
_PLACEMENT = ('CLUSTER', 'NAMESPACE', 'DEPLOYMENT')


def dedup_for_audit(df: pd.DataFrame) -> tuple:
    """(one row per distinct finding, the placement rows keyed back to it).

    RHACS emits a row per workload, so an image running in forty namespaces
    carries every one of its findings forty times.  On the reference report that
    is 376,808 rows over 74,116 distinct findings, and at 13 ms a verdict the
    duplicates alone are an hour of engine.  Audit the distinct set, then join
    the verdict back onto every row so the page still counts what RHACS reported.
    """
    if df.empty:
        return df, df
    place = [c for c in _PLACEMENT if c in df.columns]
    keys = [c for c in df.columns if c not in place]
    seen, uid, first = {}, [], []
    for pos, key in enumerate(zip(*(df[c] for c in keys))):
        code = seen.get(key)
        if code is None:
            code = seen[key] = len(seen)
            first.append(pos)
        uid.append(code)
    df = df.copy()
    df['_UID'] = uid
    return df.iloc[first].reset_index(drop=True), df[['_UID', *place]]


def expand_verdicts(result: pd.DataFrame, placement: pd.DataFrame) -> pd.DataFrame:
    """Put the deduped verdicts back on every workload row they came from."""
    if result.empty or placement.empty or '_UID' not in result.columns:
        return result.drop(columns=['_UID'], errors='ignore')
    order = [c for c in result.columns if c != '_UID']
    result = result.copy()
    result['_ORD'] = range(len(result))
    out = (result.drop(columns=list(_PLACEMENT), errors='ignore')
           .merge(placement, on='_UID', how='inner')
           .sort_values('_ORD', kind='stable')
           .reset_index(drop=True))
    return out[order]


def placements(report_rows) -> list:
    """Distinct (cluster, namespace, deployment) an image runs as, from the CSV."""
    seen = {(str(r.get('Cluster') or ''), str(r.get('Namespace') or ''),
             str(r.get('Deployment') or '')) for r in report_rows}
    return sorted(seen) or [('', '', '')]


def rescan_rows(image_ref: str, report_rows, platform: str = 'linux/amd64',
                index: dict = None) -> tuple:
    """Findings from a live scan of the image, placed where the CSV says it runs.

    The report is a snapshot of whatever RHACS knew when it was written, from
    whatever vulnerability data that version carried.  Scanning now answers the
    same question against today's data, and running both is how you see what
    moved.  Topology still comes from the CSV — a scanner knows the image, only
    the cluster knows where it is deployed — so each finding is repeated once per
    workload carrying that image.
    """
    from . import scanfree
    from .adapters import grype as adapter
    sbom = adapter.syft_sbom(image_ref, platform=platform)
    df = adapter.to_df(adapter.grype_scan(sbom))
    labels = adapter.sbom_labels(sbom) or {}
    if index:
        df, _added = scanfree.merge_index_candidates(df, index, image_ref=image_ref,
                                                     labels=labels)
    # One row per finding, with every workload carrying the image listed on it.
    # Repeating the finding per placement instead multiplies a 3,500-candidate
    # scan by however many namespaces run that image — 63,244 rows for three
    # images on the reference report, for three images' worth of information.
    spots = placements(report_rows)
    df['CLUSTER'] = ', '.join(sorted({c for c, _n, _d in spots if c}))
    df['NAMESPACE'] = ', '.join(sorted({n for _c, n, _d in spots if n}))
    df['DEPLOYMENT'] = ', '.join(sorted({d for _c, _n, d in spots if d}))
    df['IMAGE'] = image_ref
    return df, labels, adapter.sbom_digests(sbom) or [], sbom


def redhat_build(labels: dict) -> bool:
    """Is this image a Red Hat build, by its own labels?

    Red Hat's build system stamps `com.redhat.component` on everything it
    produces, and `vendor` names Red Hat.  Deciding by registry host instead
    would be a guess: a mirrored or relocated Red Hat image keeps its labels and
    loses its hostname.
    """
    labels = labels or {}
    if labels.get('com.redhat.component') or labels.get('com.redhat.build-host'):
        return True
    return 'red hat' in str(labels.get('vendor') or '').lower()


def operator_identity(labels: dict) -> tuple:
    """(component, version, release) as the Red Hat build stamped them."""
    labels = labels or {}
    return (str(labels.get('com.redhat.component') or labels.get('name') or ''),
            str(labels.get('version') or ''), str(labels.get('release') or ''))


# Verdict columns for a row nothing in the corpus can speak about.  Leaving the
# engine's answer in place would be worse than saying nothing: Red Hat publishes
# no VEX for a third-party image, and the engine reads that silence as "not
# affected" — a kafka CVE comes back FALSE POSITIVE and an openssl one is judged
# against a RHEL the image does not run.
_NOT_REDHAT = {'AUDIT_RESULT': '⚪ NOT RED HAT', 'VEX_FIX_VER': '',
               'JUSTIFICATION': 'Not a Red Hat build — Red Hat publishes no VEX '
                                'for it, so silence in the corpus is not evidence. '
                                'The scanner finding stands as reported.',
               'VEX_STATE': 'Not assessed', 'VEX_STATED': False,
               'VEX_PRODUCT': '', 'SEVERITY_MISMATCH': False}


def mark_not_redhat(df: pd.DataFrame) -> pd.DataFrame:
    """Replace engine verdicts with an explicit non-verdict."""
    if df is None or df.empty:
        return df
    df = df.copy()
    for col, val in _NOT_REDHAT.items():
        if col in df.columns or col in ('AUDIT_RESULT', 'JUSTIFICATION', 'VEX_STATE'):
            df[col] = val
    if 'SEVERITY' in df.columns and 'RHACS_SEVERITY' in df.columns:
        df['SEVERITY'] = df['RHACS_SEVERITY']
    return df


def image_job(image_ref: str, report_rows, platform: str = 'linux/amd64',
              rescan: bool = False, index: dict = None) -> dict:
    """Everything one image needs before a verdict: scan, context, candidate rows.

    This half is subprocesses and registry traffic (syft, grype), so it is what
    the thread pool is for.  The engine that follows is pure Python and gains
    nothing from threads while multiplying the resident VEX set by the worker
    count, which is why the two phases are split.
    """
    from .context import context_for_image
    error = ''
    if rescan:
        try:
            df, labels, digests, _sbom = rescan_rows(image_ref, report_rows,
                                                     platform, index)
            versioned = True
        except Exception as e:
            error = f'{type(e).__name__}: {str(e)[:120]}'
            df, labels, digests, versioned = pd.DataFrame(), {}, [], False
    else:
        facts = image_facts(image_ref, platform)
        df = rows_for_image(report_rows, facts)
        labels, digests = facts['labels'], facts['digests']
        error, versioned = facts['error'], bool(facts['packages'])
    uniq, placement = dedup_for_audit(df)
    ctx = context_for_image(image_ref, labels=labels or None, digests=digests)
    comp, ver, rel = operator_identity(labels)
    # An image we could not read is unknown, not foreign: a failed pull is a
    # statement about the registry, never about who built the image.
    redhat = None if error and not labels else redhat_build(labels)
    return {'ref': image_ref, 'ocp': ocp_version(labels),
            'display': getattr(ctx, 'display_name', ''), 'error': error,
            'versioned': versioned, 'ctx': ctx, 'df': uniq,
            'placement': placement, 'reported': len(df),
            'redhat': redhat, 'component': comp, 'version': ver, 'release': rel}


def triage_image(image_ref: str, report_rows, platform: str = 'linux/amd64',
                 rescan: bool = False, index: dict = None) -> dict:
    """Engine verdicts for one image, from the report's rows or from a fresh scan."""
    from .triage import audit_batch
    job = image_job(image_ref, report_rows, platform, rescan, index)
    result = audit_batch([job], vex_product=False)[0]
    return {k: v for k, v in job.items() if k not in ('ctx', 'df', 'placement')} | \
           {'rows': expand_verdicts(result, job['placement'])}


def triage_report(csv_path: str, *, workers: int = 4, platform: str = 'linux/amd64',
                  console=None, rescan: bool = False, ocp: str = '') -> dict:
    """Run the whole report through the engine.  Returns rows plus topology."""
    df = read_report(csv_path)
    if console:
        console.print(f"📄 {len(df):,} rows · {df['Cluster'].nunique()} cluster(s) · "
                      f"{df['Image'].nunique()} image(s)"
                      + (' · [bold]live rescan[/bold]' if rescan else ''))
    index = None
    if rescan:
        from . import scanfree
        index = scanfree.load_index() or None
        if console and not index:
            console.print('[yellow]no VEX index — rescan covers the scanner classes '
                          'only; `vextriage build-index` adds rpm + image[/yellow]')
    else:
        df = expand_errata(df, progress=(lambda m: console.print(f"   {m}")) if console else None)

    # Keyed on the digest, not the pull ref: one build reached through two repo
    # paths (a mirror, a different namespace) is one image and deserves one scan.
    # The syft cache keys on the ref, so without this the same layers are pulled
    # and SBOM-ed once per path.
    #
    # Topology comes from the CSV, always, and never from the verdict rows: in
    # rescan mode a row lists every workload carrying its image in one joined
    # cell, so counting distinct cells there would call twelve namespaces one.
    # Both are read in the one pass the records are materialised for — on a
    # 376,808-row report each extra `to_dict` is a second copy of the whole CSV.
    by_image, ref_for, spots = defaultdict(list), {}, set()
    named = df['Image'].nunique()
    # Only what rows_for_image and the topology scan read.  A record dict costs
    # about as much as its key count, and a RHACS export carries four columns
    # (Component Version, NVDCVSS, EPSS, Discovered At) nothing downstream
    # opens — dropping them first is ~140 MB off a 376,808-row report.
    df = df[[c for c in _CARRIED if c in df.columns]]
    for rec in df.to_dict('records'):
        key = digest_key(rec['Image'])
        by_image[key].append(rec)
        ref = ref_for.setdefault(key, rec['Image'])
        spots.add((str(rec.get('Cluster') or ''), str(rec.get('Namespace') or ''),
                   str(rec.get('Deployment') or ''), ref))
    spots = sorted(spots)
    del df
    if console and len(ref_for) < named:
        console.print(f"   {named - len(ref_for)} duplicate image(s) "
                      f"collapsed by digest")

    # Phase 1 — scan.  Subprocess work, so threads buy real parallelism.
    jobs, done = [], 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(image_job, ref_for[key], rows, platform, rescan, index):
                   ref_for[key] for key, rows in by_image.items()}
        total = len(by_image)
        by_image.clear()   # the futures own the rows now; free each as it finishes
        for fut in as_completed(futures):
            ref = futures[fut]
            done += 1
            try:
                job = fut.result()
            except Exception as e:
                job = {'ref': ref, 'ocp': '', 'display': '', 'versioned': False,
                       'error': f'{type(e).__name__}: {str(e)[:120]}',
                       'ctx': None, 'df': pd.DataFrame(),
                       'placement': pd.DataFrame(), 'reported': 0}
            jobs.append(job)
            if console:
                mark = '[red]![/red]' if job['error'] else '[green]✓[/green]'
                console.print(f"  [{done}/{total}] {mark} {ref.split('@')[0][-52:]}",
                              highlight=False)

    # Phase 2 — verdicts, single-threaded and CVE-major so each VEX document is
    # read once for the whole report and freed before the next one.
    reported = sum(j['reported'] for j in jobs)
    audited = sum(len(j['df']) for j in jobs)
    if console:
        console.print(f"   {audited:,} distinct finding(s) to audit"
                      + (f" ({reported:,} report rows, {reported / audited:.1f}× repeats "
                         f"across workloads)" if audited and reported > audited else ''))
    from .triage import audit_batch
    tick = (lambda n, total: console.print(f"   [{n}/{total}] CVEs audited", end='\r')
            if console and (n % 50 == 0 or n == total) else None)
    verdicts = audit_batch(jobs, vex_product=False, progress=tick)
    if console:
        console.print()

    results = []
    for job, res in zip(jobs, verdicts):
        info = {k: v for k, v in job.items()
                if k not in ('ctx', 'df', 'placement', 'reported')}
        rows_ = expand_verdicts(res, job['placement'])
        if job.get('redhat') is False:
            rows_ = mark_not_redhat(rows_)
        # Fields the report views group by, carried per image so the page can
        # answer "which operator, which OpenShift" without re-reading anything.
        if rows_ is not None and not rows_.empty:
            rows_ = rows_.copy()
            rows_['OCP_VERSION'] = job.get('ocp', '')
            rows_['BUILD_VERSION'] = job.get('version', '')
            rows_['OPERATOR'] = job.get('component', '')
            rows_['OPERATOR_VERSION'] = job.get('version', '')
            rows_['OPERATOR_RELEASE'] = job.get('release', '')
            rows_['BUILD'] = ('Red Hat' if job.get('redhat') else
                              'unreadable' if job.get('redhat') is None else 'third party')
        info['rows'] = rows_
        results.append(info)
    del jobs

    for info in results:
        r = info['rows']
        info['candidates'] = 0 if r is None else len(r)
        info['findings'] = 0 if r is None or r.empty else \
            int((~r['AUDIT_RESULT'].str.contains('FALSE', na=False)).sum())

    frames = [r['rows'] for r in results if r['rows'] is not None and not r['rows'].empty]
    rows = pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()
    return {'rows': rows, 'images': results, 'source': os.path.basename(csv_path),
            'rescan': rescan,
            'ocp_stated': [v.strip() for v in str(ocp or '').split(',') if v.strip()], 'placements': spots,
            'mode': 'live scan (syft + grype + VEX index)' if rescan
                    else 'findings as reported by RHACS'}


# ── HTML ──────────────────────────────────────────────────────────────────────
#
# Same three views, same seven filters and same CSV export as triage.html, with
# the data inlined instead of queried out of parquet through DuckDB.  Inlining
# it row-wise is what made the first attempt 16 MB on a 376,808-row report: every
# row repeated its cluster, namespace, deployment, image, operator and
# justification as full strings.  The payload below is columnar and
# dictionary-encoded — each distinct string is stored once and referenced by
# index — which is the same trick parquet uses and costs one lookup in the view.

_COLS = ('cve', 'comp', 'ver', 'cluster', 'ns', 'dep', 'image', 'operator',
         'opver', 'ocp', 'build', 'triage', 'sev', 'rsev', 'state', 'fix',
         'source', 'why')

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>__CSS__</style>
</head><body>
<div class="app">
  <header>
    <h1>RHACS Report Triage</h1>
    <p class="sub">__SOURCE__ · __WHEN__ · __OCP__</p>
    <p class="sub">__MODE__ · __IMAGES__ images · __CLUSTERS__ clusters</p>
  </header>
  <nav class="tabs">
    <button class="tab-btn active" data-tab="overview">Overview</button>
    <button class="tab-btn" data-tab="triage">Triage</button>
    <button class="tab-btn" data-tab="insights">Insights</button>
  </nav>

  <section id="overview" class="tab-panel active">
    <div class="tiles" id="tiles"></div>
    <h2>Clusters</h2><div class="grid" id="clusters"></div>
    <h2>Operator inventory</h2><div class="tablewrap"><table id="operators"><thead><tr>
      <th>Operator</th><th>Version</th><th>OpenShift</th><th>Build</th>
      <th>Positive CVEs</th><th>False positive CVEs</th>
      <th>Critical</th><th>Important</th><th>Moderate</th></tr></thead><tbody></tbody></table></div>
    <h2>Images</h2><div class="tablewrap"><table id="images"><thead><tr>
      <th>Image</th><th>OpenShift</th><th>Build</th><th>Namespaces</th>
      <th>CVEs</th><th>Critical</th><th>Important</th><th>Findings</th><th></th>
      </tr></thead><tbody></tbody></table></div>
  </section>

  <section id="triage" class="tab-panel">
    <div class="filters" id="filters"></div>
    <div class="filterbar">
      <input id="q" type="search" placeholder="filter by CVE, component, namespace, deployment, reason…">
      <button id="reset" class="btn">clear filters</button>
      <button id="export" class="btn">export CSV</button>
      <span id="count" class="count"></span>
    </div>
    <div class="tablewrap"><table id="rows"><thead><tr>
      <th>Triage</th><th>CVE</th><th>RHACS sev</th><th>VEX sev</th><th>Component</th>
      <th>Version</th><th>Fix</th><th>Cluster</th><th>Namespace</th><th>Deployment</th>
      <th>Why</th></tr></thead><tbody></tbody></table></div>
  </section>

  <section id="insights" class="tab-panel">
    <h2>CVEs by reach</h2><div class="tablewrap"><table id="bycve"><thead><tr>
      <th>Triage</th><th>CVE</th><th>VEX sev</th><th>Components</th><th>Source</th>
      <th>Images</th><th>Deployments</th><th>Fix</th><th>Findings</th>
      </tr></thead><tbody></tbody></table></div>
    <h2>Components by reach</h2><div class="tablewrap"><table id="bycomp"><thead><tr>
      <th>Component</th><th>Source</th><th>CVEs</th><th>Positive</th>
      <th>Images</th><th>Findings</th></tr></thead><tbody></tbody></table></div>
  </section>
</div>
<script id="data" type="application/gzip;base64">__DATA__</script>
<script>__JS__</script>
</body></html>
"""

_CSS = """
:root{--bg:#fff;--panel:#f7f7f8;--text:#1a1a1a;--muted:#6a6a70;--border:#e0e0e3;
--accent:#0066cc;--red:#c9190b;--green:#3d7317;--amber:#c58c00;--grey:#8a8a92}
@media (prefers-color-scheme:dark){:root{--bg:#151517;--panel:#1d1d20;--text:#e8e8ea;
--muted:#9a9aa2;--border:#33333a;--accent:#58a6ff;--red:#ff7b72;--green:#7ee787;
--amber:#e3b341;--grey:#9a9aa2}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 'Red Hat Text',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.app{max-width:1680px;margin:0 auto;padding:1.4rem 1.8rem}
header{border-bottom:1px solid var(--border);padding-bottom:.7rem}
h1{font-size:1.25rem;margin:0}h2{font-size:.95rem;margin:1.5rem 0 .55rem}
.sub{color:var(--muted);font-size:.8rem;margin:.25rem 0 0}
.tabs{display:flex;border-bottom:2px solid var(--border);margin:1rem 0 1.2rem}
.tab-btn{padding:.5rem 1.1rem;font:inherit;font-size:.82rem;font-weight:600;color:var(--muted);
border:0;background:none;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-2px}
.tab-btn:hover{color:var(--text)}
.tab-btn.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-panel{display:none}.tab-panel.active{display:block}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(128px,1fr));gap:.65rem}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.65rem .85rem}
.tile .n{font-size:1.45rem;font-weight:700}
.tile .l{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
.tile.real .n{color:var(--red)}.tile.fp .n{color:var(--green)}.tile.nrh .n{color:var(--grey)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:.65rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.75rem}
.card h3{margin:0 0 .45rem;font-size:.85rem;word-break:break-all}
.row{display:flex;justify-content:space-between;font-size:.75rem;padding:.08rem 0}
.row .k{color:var(--muted)}.row .v{font-weight:600}
.tablewrap{overflow-x:auto;max-height:70vh;overflow-y:auto;border:1px solid var(--border);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:.78rem}
th,td{text-align:left;padding:.4rem .58rem;border-bottom:1px solid var(--border);white-space:nowrap}
th{background:var(--panel);position:sticky;top:0;z-index:1;font-size:.7rem;
text-transform:uppercase;letter-spacing:.04em;color:var(--muted);cursor:pointer;user-select:none}
th:hover{color:var(--text)}
td.why{white-space:normal;min-width:280px;max-width:520px;color:var(--muted)}
td.wrap{white-space:normal;max-width:340px;word-break:break-all}
tbody tr:hover{background:var(--panel)}
.t-P{color:var(--red);font-weight:700}.t-FP{color:var(--green);font-weight:700}
.t-NRH{color:var(--grey);font-weight:700}
.s-Critical{color:var(--red);font-weight:700}.s-Important{color:var(--red)}
.s-Moderate{color:var(--amber)}.s-Low{color:var(--muted)}
.filters{display:flex;flex-wrap:wrap;gap:.9rem;margin:.2rem 0 .5rem}
.fgroup{border:1px solid var(--border);border-radius:9px;padding:.4rem .55rem;background:var(--panel)}
.fgroup h4{margin:0 0 .3rem;font-size:.66rem;text-transform:uppercase;
letter-spacing:.05em;color:var(--muted);font-weight:700}
.chips{display:flex;flex-wrap:wrap;gap:.25rem;max-height:5.4rem;overflow-y:auto;max-width:460px}
.chip{font-size:.71rem;padding:.13rem .45rem;border:1px solid var(--border);border-radius:999px;
cursor:pointer;background:var(--bg);color:var(--muted);white-space:nowrap}
.chip:hover{color:var(--text)}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:600}
.filterbar{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.35rem 0 .6rem}
input,.btn{background:var(--bg);color:var(--text);border:1px solid var(--border);
border-radius:7px;padding:.35rem .55rem;font:inherit;font-size:.78rem}
input#q{min-width:340px;flex:1}
.btn{cursor:pointer;font-weight:600}.btn:hover{border-color:var(--accent);color:var(--accent)}
.count{color:var(--muted);font-size:.75rem}
.warn{color:var(--amber);white-space:normal}
"""

_JS = r"""
// The payload is gzipped and base64'd: as plain JSON the reference report is
// 19 MB of index arrays, which is not something anyone wants to email.
// DecompressionStream is standard in every current browser.
async function payload() {
  const b64 = document.getElementById('data').textContent.trim();
  const bin = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const stream = new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(stream).text());
}
let D, N, DICT, COL;
// Every column is an index into its own dictionary; val() is the only decode.
const val = (c, i) => DICT[c][COL[c][i]];
const esc = s => String(s ?? '').replace(/[&<>"]/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const num = n => n.toLocaleString();
const TRI = {P: 'real', FP: 'false positive', NRH: 'not Red Hat'};
const SEP = '\u0001';
const SEVS = ['Critical', 'Important', 'Moderate', 'Low', 'Unknown'];

// ── filters ───────────────────────────────────────────────────────────────
const FILTERS = [['triage', 'Triage'], ['sev', 'VEX severity'], ['cluster', 'Cluster'],
                 ['ns', 'Namespace'], ['dep', 'Deployment'], ['fixable', 'Fixable'],
                 ['comp', 'Component'], ['build', 'Build'], ['ocp', 'OpenShift']];
const state = {};
FILTERS.forEach(([k]) => state[k] = new Set());
let term = '', view = [];

const fixable = i => (val('fix', i) && val('fix', i) !== '-' && val('fix', i) !== 'N/A')
  ? 'fixable' : 'no fix';

function options(key) {
  if (key === 'fixable') return ['fixable', 'no fix'];
  if (key === 'triage') return ['P', 'FP', 'NRH'].filter(t => DICT.triage.includes(t));
  if (key === 'sev') return SEVS.filter(s => DICT.sev.includes(s));
  return [...DICT[key]].filter(Boolean).sort();
}

function passes(i) {
  for (const [k] of FILTERS) {
    if (!state[k].size) continue;
    const v = k === 'fixable' ? fixable(i) : val(k, i);
    if (!state[k].has(v)) return false;
  }
  if (term) {
    const hay = (val('cve', i) + ' ' + val('comp', i) + ' ' + val('ns', i) + ' ' +
                 val('dep', i) + ' ' + val('why', i) + ' ' + val('image', i)).toLowerCase();
    if (!hay.includes(term)) return false;
  }
  return true;
}

function apply() {
  view = [];
  for (let i = 0; i < N; i++) if (passes(i)) view.push(i);
}

function renderFilters() {
  document.getElementById('filters').innerHTML = FILTERS.map(([k, label]) => {
    const opts = options(k);
    if (!opts.length) return '';
    return `<div class="fgroup"><h4>${label}</h4><div class="chips">` +
      opts.map(o => `<span class="chip${state[k].has(o) ? ' on' : ''}" data-k="${k}" ` +
        `data-v="${esc(o)}">${esc(k === 'triage' ? TRI[o] : o)}</span>`).join('') +
      `</div></div>`;
  }).join('');
  document.querySelectorAll('.chip').forEach(el => el.onclick = () => {
    const k = el.dataset.k, v = el.dataset.v;
    state[k].has(v) ? state[k].delete(v) : state[k].add(v);
    renderFilters(); renderRows();
  });
}

// ── triage table ──────────────────────────────────────────────────────────
let sortCol = null, sortDir = 1;
const ROWCOLS = ['triage', 'cve', 'rsev', 'sev', 'comp', 'ver', 'fix', 'cluster',
                 'ns', 'dep', 'why'];
const LIMIT = 2500;

function renderRows() {
  apply();
  let rows = view;
  if (sortCol !== null) {
    const c = ROWCOLS[sortCol];
    rows = [...view].sort((a, b) => String(val(c, a)).localeCompare(String(val(c, b))) * sortDir);
  }
  document.getElementById('count').textContent =
    `${num(rows.length)} of ${num(N)} rows · ${num(new Set(rows.map(i => val('cve', i))).size)} CVEs`;
  const body = rows.slice(0, LIMIT).map(i => `<tr>
    <td class="t-${val('triage', i)}">${TRI[val('triage', i)]}</td>
    <td>${esc(val('cve', i))}</td><td class="s-${esc(val('rsev', i))}">${esc(val('rsev', i))}</td>
    <td class="s-${esc(val('sev', i))}">${esc(val('sev', i))}</td>
    <td>${esc(val('comp', i))}</td><td>${esc(val('ver', i))}</td><td>${esc(val('fix', i))}</td>
    <td>${esc(val('cluster', i))}</td><td>${esc(val('ns', i))}</td><td>${esc(val('dep', i))}</td>
    <td class="why">${esc(val('why', i))}</td></tr>`).join('');
  document.querySelector('#rows tbody').innerHTML = body +
    (rows.length > LIMIT ? `<tr><td colspan="11" class="why">showing the first
      ${num(LIMIT)} of ${num(rows.length)} — narrow the filters to see the rest,
      or export the CSV, which contains every filtered row.</td></tr>` : '');
}

document.querySelectorAll('#rows th').forEach((th, n) => th.onclick = () => {
  sortDir = sortCol === n ? -sortDir : 1; sortCol = n; renderRows();
});

// ── overview ──────────────────────────────────────────────────────────────
const uniq = (rows, c) => new Set(rows.map(i => val(c, i))).size;
const count = (rows, c, v) => rows.reduce((a, i) => a + (val(c, i) === v ? 1 : 0), 0);
const cvesWhere = (rows, t) =>
  new Set(rows.filter(i => val('triage', i) === t).map(i => val('cve', i))).size;

function group(keyfn) {
  const m = new Map();
  for (let i = 0; i < N; i++) {
    const k = keyfn(i);
    let g = m.get(k); if (!g) m.set(k, g = []);
    g.push(i);
  }
  return m;
}

function tile(n, l, cls) {
  return `<div class="tile ${cls || ''}"><div class="n">${num(n)}</div><div class="l">${l}</div></div>`;
}

function renderOverview() {
  const all = [...Array(N).keys()];
  document.getElementById('tiles').innerHTML =
    tile(N, 'findings') +
    tile(count(all, 'triage', 'P'), 'real', 'real') +
    tile(count(all, 'triage', 'FP'), 'false positive', 'fp') +
    tile(count(all, 'triage', 'NRH'), 'not Red Hat', 'nrh') +
    tile(uniq(all, 'cve'), 'CVEs') +
    tile(uniq(all, 'image'), 'images') +
    tile(uniq(all, 'cluster'), 'clusters') +
    tile(uniq(all, 'ns'), 'namespaces') +
    tile(uniq(all, 'dep'), 'deployments');

  document.getElementById('clusters').innerHTML = [...group(i => val('cluster', i))]
    .sort((a, b) => b[1].length - a[1].length).map(([name, rows]) => `<div class="card">
      <h3>${esc(name || '—')}</h3>
      <div class="row"><span class="k">findings</span><span class="v">${num(rows.length)}</span></div>
      <div class="row"><span class="k">real</span><span class="v">${num(count(rows, 'triage', 'P'))}</span></div>
      <div class="row"><span class="k">CVEs</span><span class="v">${num(uniq(rows, 'cve'))}</span></div>
      <div class="row"><span class="k">images</span><span class="v">${num(uniq(rows, 'image'))}</span></div>
      <div class="row"><span class="k">namespaces</span><span class="v">${num(uniq(rows, 'ns'))}</span></div>
      <div class="row"><span class="k">deployments</span><span class="v">${num(uniq(rows, 'dep'))}</span></div>
    </div>`).join('');

  document.querySelector('#operators tbody').innerHTML =
    [...group(i => val('operator', i) + SEP + val('opver', i))]
      .sort((a, b) => cvesWhere(b[1], 'P') - cvesWhere(a[1], 'P')).map(([k, rows]) => {
        const [op, ver] = k.split(SEP);
        return `<tr><td class="wrap">${esc(op || '—')}</td><td>${esc(ver)}</td>
          <td>${esc(val('ocp', rows[0]))}</td><td>${esc(val('build', rows[0]))}</td>
          <td class="t-P">${num(cvesWhere(rows, 'P'))}</td>
          <td class="t-FP">${num(cvesWhere(rows, 'FP'))}</td>
          <td>${num(count(rows, 'sev', 'Critical'))}</td>
          <td>${num(count(rows, 'sev', 'Important'))}</td>
          <td>${num(count(rows, 'sev', 'Moderate'))}</td></tr>`;
      }).join('');

  document.querySelector('#images tbody').innerHTML = [...group(i => val('image', i))]
    .sort((a, b) => cvesWhere(b[1], 'P') - cvesWhere(a[1], 'P')).map(([img, rows]) => `<tr>
      <td class="wrap">${esc(img.split('@')[0])}</td><td>${esc(val('ocp', rows[0]))}</td>
      <td>${esc(val('build', rows[0]))}</td><td>${num(uniq(rows, 'ns'))}</td>
      <td>${num(uniq(rows, 'cve'))}</td>
      <td>${num(count(rows, 'sev', 'Critical'))}</td>
      <td>${num(count(rows, 'sev', 'Important'))}</td>
      <td class="t-P">${num(count(rows, 'triage', 'P'))}</td>
      <td class="warn">${esc(D.errors[img] || '')}</td></tr>`).join('');
}

// ── insights ──────────────────────────────────────────────────────────────
function renderInsights() {
  document.querySelector('#bycve tbody').innerHTML = [...group(i => val('cve', i))]
    .sort((a, b) => b[1].length - a[1].length).slice(0, 400).map(([cve, rows]) => {
      const comps = [...new Set(rows.map(i => val('comp', i)))];
      return `<tr><td class="t-${val('triage', rows[0])}">${TRI[val('triage', rows[0])]}</td>
        <td>${esc(cve)}</td><td class="s-${esc(val('sev', rows[0]))}">${esc(val('sev', rows[0]))}</td>
        <td class="wrap">${esc(comps.slice(0, 4).join(', '))}${comps.length > 4 ? ` +${comps.length - 4}` : ''}</td>
        <td>${esc(val('source', rows[0]))}</td><td>${num(uniq(rows, 'image'))}</td>
        <td>${num(uniq(rows, 'dep'))}</td><td>${esc(val('fix', rows[0]))}</td>
        <td>${num(rows.length)}</td></tr>`;
    }).join('');

  document.querySelector('#bycomp tbody').innerHTML = [...group(i => val('comp', i))]
    .sort((a, b) => b[1].length - a[1].length).slice(0, 400).map(([comp, rows]) => `<tr>
      <td class="wrap">${esc(comp)}</td><td>${esc(val('source', rows[0]))}</td>
      <td>${num(uniq(rows, 'cve'))}</td><td class="t-P">${num(count(rows, 'triage', 'P'))}</td>
      <td>${num(uniq(rows, 'image'))}</td><td>${num(rows.length)}</td></tr>`).join('');
}

// ── export ────────────────────────────────────────────────────────────────
document.getElementById('export').onclick = () => {
  const cols = ['triage', 'cve', 'rsev', 'sev', 'comp', 'ver', 'fix', 'source',
                'cluster', 'ns', 'dep', 'image', 'operator', 'opver', 'ocp',
                'build', 'state', 'why'];
  const q = s => `"${String(s ?? '').replace(/"/g, '""')}"`;
  const csv = [cols.join(',')].concat(
    view.map(i => cols.map(c => q(c === 'triage' ? TRI[val(c, i)] : val(c, i))).join(','))
  ).join('\n');
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([csv], {type: 'text/csv'}));
  a.download = 'triage-filtered.csv';
  a.click();
  URL.revokeObjectURL(a.href);
};

document.getElementById('reset').onclick = () => {
  FILTERS.forEach(([k]) => state[k].clear());
  term = ''; document.getElementById('q').value = '';
  renderFilters(); renderRows();
};
document.getElementById('q').oninput = e => { term = e.target.value.trim().toLowerCase(); renderRows(); };
document.querySelectorAll('.tab-btn').forEach(b => b.onclick = () => {
  document.querySelectorAll('.tab-btn').forEach(x => x.classList.toggle('active', x === b));
  document.querySelectorAll('.tab-panel').forEach(p =>
    p.classList.toggle('active', p.id === b.dataset.tab));
});

payload().then(p => {
  D = p; N = D.n; DICT = D.dict; COL = D.cols;
  renderOverview(); renderFilters(); renderRows(); renderInsights();
}).catch(e => {
  document.querySelector('.app').insertAdjacentHTML('beforeend',
    `<p class="warn">could not read the embedded data: ${e}</p>`);
});
"""


def _encode(rows: pd.DataFrame) -> dict:
    """Columnar, dictionary-encoded payload — one copy of each distinct string."""
    def col(series, cast=str):
        vals, index, out = [], {}, []
        for v in series:
            s = cast(v) if v is not None else ''
            code = index.get(s)
            if code is None:
                code = index[s] = len(vals)
                vals.append(s)
            out.append(code)
        return vals, out

    def triage(v):
        v = str(v)
        return 'NRH' if 'NOT RED HAT' in v else ('FP' if 'FALSE' in v else 'P')

    src = {
        'cve': rows.get('CVE', ''), 'comp': rows.get('COMPONENT', ''),
        'ver': rows.get('VERSION', ''), 'cluster': rows.get('CLUSTER', ''),
        'ns': rows.get('NAMESPACE', ''), 'dep': rows.get('DEPLOYMENT', ''),
        'image': rows.get('IMAGE', ''), 'operator': rows.get('OPERATOR', ''),
        'opver': rows.get('OPERATOR_VERSION', ''), 'ocp': rows.get('OCP_VERSION', ''),
        'build': rows.get('BUILD', ''), 'sev': rows.get('SEVERITY', ''),
        'bver': rows.get('BUILD_VERSION', ''),
        'rsev': rows.get('RHACS_SEVERITY', ''), 'state': rows.get('VEX_STATE', ''),
        'fix': rows.get('VEX_FIX_VER', ''), 'source': rows.get('SOURCE', ''),
        'why': rows.get('JUSTIFICATION', ''),
    }
    dict_, cols = {}, {}
    for name, series in src.items():
        if series is None or isinstance(series, str):
            series = [''] * len(rows)
        dict_[name], cols[name] = col(series)
    dict_['triage'], cols['triage'] = col(rows['AUDIT_RESULT'], triage)
    return {'n': len(rows), 'dict': dict_, 'cols': cols}


def _packed(payload: dict) -> str:
    """gzip + base64 the payload; base64's 4/3 overhead is far under the win."""
    import base64
    import gzip
    raw = json.dumps(payload, separators=(',', ':')).encode()
    return base64.b64encode(gzip.compress(raw, 6)).decode()


def render_html(result: dict, path: str, *, when: str = '') -> str:
    """Write the whole triaged report as one self-contained page."""
    rows = result['rows']
    if rows is None or rows.empty:
        raise ValueError('no rows to render')
    ocp = sorted(result.get('ocp_stated') or
                 {i['ocp'] for i in result['images'] if i.get('ocp')})
    payload = _encode(rows)
    payload['errors'] = {i['ref']: i['error'] for i in result['images'] if i.get('error')}
    html = (_PAGE
            .replace('__TITLE__', f'RHACS Report Triage — {result["source"]}')
            .replace('__CSS__', _CSS)
            .replace('__JS__', _JS)
            .replace('__SOURCE__', result['source'])
            .replace('__WHEN__', when or '')
            .replace('__OCP__', ('OpenShift ' + ', '.join(ocp)) if ocp
                     else 'OpenShift version unknown')
            .replace('__MODE__', result.get('mode', ''))
            .replace('__IMAGES__', f'{len(result["images"]):,}')
            .replace('__CLUSTERS__', f'{rows["CLUSTER"].nunique() if len(rows) else 0:,}')
            .replace('__DATA__', _packed(payload)))
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    return path


def write_parquet(result: dict, path: str) -> str:
    """The same rows the page shows, as a parquet the explorer can query.

    triage.html reads parquet through DuckDB WASM and already has the views and
    filters; handing it one file per report means those keep working without the
    OCP pipeline having produced anything.  The HTML stays the thing you email,
    this stays the thing you query.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq
    rows = result['rows']
    if rows is None or rows.empty:
        raise ValueError('no rows to write')
    out = rows.copy()
    out['TRIAGE_STATUS'] = out['AUDIT_RESULT'].map(
        lambda v: 'NOT RED HAT' if 'NOT RED HAT' in str(v)
        else ('FALSE POSITIVE' if 'FALSE' in str(v) else 'POSITIVE'))
    # Dictionary-encode the columns that repeat across every row of an image;
    # on the reference report that is the difference between 130 MB and a few.
    table = pa.Table.from_pandas(out, preserve_index=False)
    pq.write_table(table, path, compression='zstd', use_dictionary=True)
    return path
