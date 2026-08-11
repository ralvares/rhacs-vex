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
    """OpenShift version an image was built for, read from its labels."""
    labels = labels or {}
    for key in ('io.openshift.release', 'io.openshift.build.versions',
                'io.openshift.version'):
        val = str(labels.get(key) or '')
        m = re.search(r'(\d+\.\d+(?:\.\d+)?)', val)
        if m:
            return m.group(1)
    ver = str(labels.get('version') or '')
    m = re.match(r'v?(\d+\.\d+(?:\.\d+)?)', ver)
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
    return {'ref': image_ref, 'ocp': ocp_version(labels),
            'display': getattr(ctx, 'display_name', ''), 'error': error,
            'versioned': versioned, 'ctx': ctx, 'df': uniq,
            'placement': placement, 'reported': len(df)}


def triage_image(image_ref: str, report_rows, platform: str = 'linux/amd64',
                 rescan: bool = False, index: dict = None) -> dict:
    """Engine verdicts for one image, from the report's rows or from a fresh scan."""
    from .triage import audit_batch
    job = image_job(image_ref, report_rows, platform, rescan, index)
    result = audit_batch([job], vex_product=False)[0]
    return {k: v for k, v in job.items() if k not in ('ctx', 'df', 'placement')} | \
           {'rows': expand_verdicts(result, job['placement'])}


def triage_report(csv_path: str, *, workers: int = 4, platform: str = 'linux/amd64',
                  console=None, rescan: bool = False) -> dict:
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
        info['rows'] = expand_verdicts(res, job['placement'])
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
            'rescan': rescan, 'placements': spots,
            'mode': 'live scan (syft + grype + VEX index)' if rescan
                    else 'findings as reported by RHACS'}


# ── HTML ──────────────────────────────────────────────────────────────────────

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>__CSS__</style>
</head><body><div class="app">
<header>
  <h1>RHACS Report Triage</h1>
  <p class="sub">__SOURCE__ · generated __WHEN__ · __OCP__</p>
  <p class="sub">source of findings: __MODE__</p>
</header>
<section class="tiles">__TILES__</section>
<section><h2>Clusters</h2><div class="grid">__CLUSTERS__</div></section>
<section><h2>Images</h2><div class="tablewrap">__IMAGES__</div></section>
<section>
  <h2>Findings</h2>
  <div class="filters">
    <input id="q" type="search" placeholder="filter by CVE, component, namespace, deployment…">
    <select id="verdict"><option value="">every verdict</option>
      <option value="real">real only</option><option value="fp">false positives only</option></select>
    <select id="sev"><option value="">every severity</option>__SEVOPTS__</select>
    <select id="cluster"><option value="">every cluster</option>__CLUSTEROPTS__</select>
    <span id="count" class="count"></span>
  </div>
  <div class="tablewrap"><table id="findings"><thead><tr>
    <th>CVE</th><th>Component</th><th>Version</th><th>Verdict</th><th>Red Hat says</th>
    <th>Fix</th><th>Cluster</th><th>Namespace</th><th>Deployment</th><th>Why</th>
  </tr></thead><tbody></tbody></table></div>
</section>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>__JS__</script>
</body></html>
"""

_CSS = """
:root{--bg:#fff;--panel:#f7f7f8;--text:#1a1a1a;--muted:#6a6a70;--border:#e0e0e3;
--accent:#0066cc;--red:#c9190b;--green:#3d7317;--amber:#c58c00}
@media (prefers-color-scheme:dark){:root{--bg:#151517;--panel:#1d1d20;--text:#e8e8ea;
--muted:#9a9aa2;--border:#33333a;--accent:#58a6ff;--red:#ff7b72;--green:#7ee787;--amber:#e3b341}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 'Red Hat Text',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif}
.app{max-width:1600px;margin:0 auto;padding:1.5rem 2rem}
header{border-bottom:1px solid var(--border);padding-bottom:.8rem;margin-bottom:1.2rem}
h1{font-size:1.25rem;margin:0}h2{font-size:.95rem;margin:1.6rem 0 .6rem}
.sub{color:var(--muted);font-size:.8rem;margin:.3rem 0 0}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.7rem}
.tile{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.7rem .9rem}
.tile .n{font-size:1.5rem;font-weight:700}.tile .l{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
.tile.real .n{color:var(--red)}.tile.fp .n{color:var(--green)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.7rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.8rem}
.card h3{margin:0 0 .5rem;font-size:.85rem}
.row{display:flex;justify-content:space-between;font-size:.75rem;padding:.1rem 0}
.row .k{color:var(--muted)}.row .v{font-weight:600}
.tablewrap{overflow-x:auto;border:1px solid var(--border);border-radius:10px}
table{border-collapse:collapse;width:100%;font-size:.78rem}
th,td{text-align:left;padding:.42rem .6rem;border-bottom:1px solid var(--border);white-space:nowrap}
th{background:var(--panel);position:sticky;top:0;font-size:.72rem;text-transform:uppercase;
letter-spacing:.04em;color:var(--muted)}
td.why{white-space:normal;max-width:460px;color:var(--muted)}
tbody tr:hover{background:var(--panel)}
.v-real{color:var(--red);font-weight:700}.v-fp{color:var(--green);font-weight:700}
.sev-Critical{color:var(--red);font-weight:700}.sev-Important{color:var(--red)}
.sev-Moderate{color:var(--amber)}.sev-Low{color:var(--muted)}
.filters{display:flex;gap:.5rem;flex-wrap:wrap;align-items:center;margin:.6rem 0}
input,select{background:var(--bg);color:var(--text);border:1px solid var(--border);
border-radius:7px;padding:.35rem .5rem;font:inherit;font-size:.78rem}
input#q{min-width:320px;flex:1}
.count{color:var(--muted);font-size:.75rem}
.warn{color:var(--amber)}
"""

_JS = """
const D = JSON.parse(document.getElementById('data').textContent), S = D.s;
const ROWS = D.r.map(a => ({cve: S[a[0]], comp: S[a[1]], ver: S[a[2]], fp: !!a[3],
  sev: S[a[4]], state: S[a[5]], fix: S[a[6]], cluster: S[a[7]], ns: S[a[8]],
  dep: S[a[9]], why: S[a[10]]}));
const tb = document.querySelector('#findings tbody');
const q = document.getElementById('q'), verdict = document.getElementById('verdict');
const sev = document.getElementById('sev'), cluster = document.getElementById('cluster');
const count = document.getElementById('count');
const esc = s => String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function draw() {
  const term = q.value.trim().toLowerCase(), vf = verdict.value, sf = sev.value, cf = cluster.value;
  const hit = ROWS.filter(r =>
    (!vf || (vf === 'real' ? !r.fp : r.fp)) && (!sf || r.sev === sf) && (!cf || r.cluster.includes(cf)) &&
    (!term || (r.cve + ' ' + r.comp + ' ' + r.ns + ' ' + r.dep + ' ' + r.why).toLowerCase().includes(term)));
  count.textContent = hit.length.toLocaleString() + ' of ' + ROWS.length.toLocaleString() + ' rows';
  tb.innerHTML = hit.slice(0, 3000).map(r => `<tr>
    <td>${esc(r.cve)}</td><td>${esc(r.comp)}</td><td>${esc(r.ver)}</td>
    <td class="${r.fp ? 'v-fp' : 'v-real'}">${r.fp ? 'false positive' : 'real'}</td>
    <td class="sev-${esc(r.sev)}">${esc(r.state)}</td><td>${esc(r.fix)}</td>
    <td>${esc(r.cluster)}</td><td>${esc(r.ns)}</td><td>${esc(r.dep)}</td>
    <td class="why">${esc(r.why)}</td></tr>`).join('');
  if (hit.length > 3000) tb.insertAdjacentHTML('beforeend',
    `<tr><td colspan="10" class="why">showing the first 3,000 of ${hit.length.toLocaleString()} — narrow the filter to see the rest</td></tr>`);
}
[q, verdict, sev, cluster].forEach(el => el.addEventListener('input', draw));
draw();
"""


def _tile(n, label, cls='') -> str:
    return f'<div class="tile {cls}"><div class="n">{n:,}</div><div class="l">{label}</div></div>'


def render_html(result: dict, path: str, *, when: str = '') -> str:
    """Write the whole triaged report as one self-contained page."""
    rows = result['rows']
    # A rescan enumerates every pair the corpus could decide, so most rows were
    # never claims about this image; calling those false positives would invent a
    # scanner that never reported them.  Those rows are also 16,388 of 19,011 on
    # three images, which is 280 MB of embedded JSON across a real report — the
    # page exists to be emailed, so only the findings travel in it.
    candidates = result.get('rescan', False)
    keep = rows if rows.empty else (
        rows[~rows['AUDIT_RESULT'].str.contains('FALSE', na=False)] if candidates else rows)
    real = rows[~rows['AUDIT_RESULT'].str.contains('FALSE', na=False)] if len(rows) else rows

    # Topology is counted from the CSV's placement tuples, never from the verdict
    # rows: a rescan row lists every workload carrying its image in one cell.
    spots = result.get('placements') or []
    clusters = sorted({c for c, _n, _d, _i in spots if c})
    findings_by_ref = {i['ref']: i.get('findings', 0) for i in result['images']}
    cand_by_ref = {i['ref']: i.get('candidates', 0) for i in result['images']}

    sevs = [s for s in ('Critical', 'Important', 'Moderate', 'Low')
            if len(keep) and (keep['SEVERITY'] == s).any()]
    ocp = sorted({i['ocp'] for i in result['images'] if i['ocp']})
    failed = [i for i in result['images'] if i['error']]

    per_cluster = []
    for cl in clusters:
        here = [s for s in spots if s[0] == cl]
        imgs = {i for _c, _n, _d, i in here}
        # In report mode every row belongs to exactly one placement, so the
        # findings count is exact and the cards sum to the tile.  A rescan row
        # covers every workload running its image, so the best available number
        # is per-image — which double-counts an image deployed in two clusters.
        if candidates:
            found = sum(findings_by_ref.get(i, 0) for i in imgs)
        else:
            sub = rows[rows['CLUSTER'].astype(str) == cl] if len(rows) else rows
            found = 0 if sub.empty else \
                int((~sub['AUDIT_RESULT'].str.contains('FALSE', na=False)).sum())
        per_cluster.append(
            f'<div class="card"><h3>{cl}</h3>'
            f'<div class="row"><span class="k">findings</span><span class="v">{found:,}</span></div>'
            f'<div class="row"><span class="k">images</span><span class="v">{len(imgs):,}</span></div>'
            f'<div class="row"><span class="k">namespaces</span><span class="v">'
            f'{len({n for _c, n, _d, _i in here if n}):,}</span></div>'
            f'<div class="row"><span class="k">deployments</span><span class="v">'
            f'{len({(n, d) for _c, n, d, _i in here if d}):,}</span></div>'
            f'</div>')
    if candidates and len(clusters) > 1:
        per_cluster.append('<div class="card"><h3>reading these</h3><div class="why">'
                           'A rescan reports per image, and an image deployed in '
                           'several clusters is counted in each, so these cards total '
                           'more than the tile above.</div></div>')

    img_rows = []
    for info in sorted(result['images'], key=lambda i: -i.get('findings', 0)):
        note = (f'<span class="warn">{info["error"]}</span>' if info['error']
                else ('' if info['versioned'] else '<span class="warn">no SBOM versions</span>'))
        img_rows.append(f'<tr><td>{info["ref"].split("@")[0]}</td>'
                        f'<td>{info["ref"].split("@")[-1][:19]}…</td>'
                        f'<td>{info["ocp"] or "-"}</td>'
                        f'<td>{cand_by_ref.get(info["ref"], 0):,}</td>'
                        f'<td class="v-real">{findings_by_ref.get(info["ref"], 0):,}</td>'
                        f'<td class="why">{note}</td></tr>')

    # Dictionary-encoded, because the page is meant to be emailed: a justification
    # or a namespace repeats across hundreds of rows, and interning them cuts a
    # 103-image rescan from tens of megabytes to something sendable.  The reader
    # rehydrates in six lines of JS.
    table, index = [], {}

    def _i(value) -> int:
        v = '' if value is None else str(value)
        if v not in index:
            index[v] = len(table)
            table.append(v)
        return index[v]

    payload = [[_i(r['CVE']), _i(r['COMPONENT']), _i(r['VERSION']),
                1 if 'FALSE' in str(r['AUDIT_RESULT']) else 0,
                _i(r.get('SEVERITY', '')), _i(r.get('VEX_STATE', '')),
                _i(r.get('VEX_FIX_VER', '') or '-'), _i(r.get('CLUSTER', '')),
                _i(r.get('NAMESPACE', '')), _i(r.get('DEPLOYMENT', '')),
                _i(r.get('JUSTIFICATION', ''))]
               for r in (keep.to_dict('records') if len(keep) else [])]

    html = (_PAGE
            .replace('__TITLE__', f'RHACS Report Triage — {result["source"]}')
            .replace('__CSS__', _CSS)
            .replace('__JS__', _JS)
            .replace('__SOURCE__', result['source'])
            .replace('__WHEN__', when or '')
            .replace('__MODE__', result.get('mode', '')
                     + (' — the table lists findings only; cleared candidates are counted, '
                        'not carried' if candidates else ''))
            .replace('__OCP__', ('OpenShift ' + ', '.join(ocp)) if ocp else 'OpenShift version unknown')
            .replace('__TILES__', ''.join([
                _tile(len(rows), 'candidates' if candidates else 'findings'),
                _tile(len(real), 'findings' if candidates else 'real', 'real'),
                _tile(len(rows) - len(real),
                      'not a match' if candidates else 'false positives', 'fp'),
                _tile(len(clusters), 'clusters'),
                _tile(len({i for _c, _n, _d, i in spots}), 'images'),
                _tile(len({(c, n) for c, n, _d, _i in spots if n}), 'namespaces'),
                _tile(len({(c, n, d) for c, n, d, _i in spots if d}), 'deployments'),
                _tile(len(failed), 'images unread', 'warn' if failed else ''),
            ]))
            .replace('__CLUSTERS__', ''.join(per_cluster))
            .replace('__IMAGES__', '<table><thead><tr><th>Repository</th><th>Digest</th>'
                                   f'<th>OCP</th><th>{"Candidates" if candidates else "Rows"}</th>'
                                   '<th>Findings</th><th></th></tr>'
                                   '</thead><tbody>' + ''.join(img_rows) + '</tbody></table>')
            .replace('__SEVOPTS__', ''.join(f'<option>{s}</option>' for s in sevs))
            .replace('__CLUSTEROPTS__', ''.join(f'<option>{c}</option>' for c in clusters))
            .replace('__DATA__', json.dumps({'s': table, 'r': payload},
                                          separators=(',', ':'))))
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(html)
    return path
