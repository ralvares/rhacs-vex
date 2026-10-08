"""Run the engine over findings — the one driver every command uses.

    audit_frame(df, ctx)          one image
    audit([{'df':…, 'ctx':…}, …]) many images, CVE-major

A job is a findings DataFrame (one row per component × CVE, the columns
adapters produce) plus the WorkloadContext of the image it came from.  The
result is the same frame with the verdict columns added, sorted
false-positives-last-for-review:

    AUDIT_RESULT  VEX_FIX_VER  JUSTIFICATION  SEVERITY  VEX_STATE  VEX_STATED
    VEX_PRODUCT   RHACS_SEVERITY (scanner's)  SEVERITY_MISMATCH  FIXABLE

The walk is CVE-major: each VEX document is read once for every row anywhere
in the batch that cites it, then dropped — peak memory is one document per
worker, not an LRU of them.
"""
from __future__ import annotations

import os
from typing import Optional

import pandas as pd

from .core.decide import SEVERITY_FROM_SCANNER, triage, vex_product as _vex_product
from .core.store import read_vex

VERDICT_COLUMNS = ['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY',
                   'VEX_STATE', 'VEX_STATED']
FP = '✅ FALSE POSITIVE'

_SEVERITY_ORDER = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3, "Unknown": 4}

# Columns carried into results when the input has them.
_CARRIED = ('SOURCE', 'LOCATION', 'FIXED_VERSION', 'OCP_COMPONENT', 'IMAGE', 'IMAGE_ROLE',
            'SRPM', 'OWNER_RPM', 'PURL', 'VEX_STATED', 'ALIAS_ID', 'CLUSTER', 'NAMESPACE',
            'DEPLOYMENT', '_UID')


def audit_frame(df: pd.DataFrame, ctx, **kw) -> pd.DataFrame:
    return audit([{'df': df, 'ctx': ctx}], **kw)[0]


def audit(jobs: list, *, false_only: bool = False, vex_product: bool = True,
          progress=None, workers: int = 0) -> list:
    """Audit many (df, ctx) jobs; one sorted result frame per job, in order."""
    prepared = []
    for job in jobs:
        df = prepare(job['df'])
        prepared.append((job['ctx'], df))

    work: dict = {}                     # CVE → {job: [row positions]}
    for ji, (_ctx, df) in enumerate(prepared):
        for ri, cve in enumerate(df['CVE'] if len(df) else []):
            work.setdefault(str(cve).strip().upper(), {}).setdefault(ji, []).append(ri)

    verdicts = [[None] * len(df) for _c, df in prepared]
    products = [[''] * len(df) for _c, df in prepared]
    records = [df.to_dict('records') if len(df) else [] for _c, df in prepared]

    global _STATE
    _STATE = (prepared, records, vex_product)
    try:
        for done, got in enumerate(_map(work, _pool_size(workers, len(work))), 1):
            for ji, ri, verdict, product in got:
                verdicts[ji][ri] = verdict
                products[ji][ri] = product
            if progress:
                progress(done, len(work))
    finally:
        _STATE = None

    out = []
    for ji, (_ctx, df) in enumerate(prepared):
        if len(df):
            df[VERDICT_COLUMNS] = pd.DataFrame(verdicts[ji], index=df.index)
            df['VEX_PRODUCT'] = products[ji]
            df['SEVERITY_MISMATCH'] = ((df['RHACS_SEVERITY'] != 'Unknown')
                                       & (df['SEVERITY'] != df['RHACS_SEVERITY']))
        out.append(finalize(df, false_only))
    return out


# ── workers ──────────────────────────────────────────────────────────────────

_STATE = None   # (prepared, records, vex_product) for the duration of audit()


def _audit_cve(item) -> list:
    cve, per_job = item
    prepared, records, want_product = _STATE
    data = read_vex(cve)
    out = []
    for ji, positions in per_job.items():
        ctx = prepared[ji][0]
        for ri in positions:
            rec = records[ji][ri]
            out.append((ji, ri, triage(rec, ctx, data).as_list(),
                        _vex_product(data, str(rec.get('COMPONENT', '')), ctx)
                        if want_product else ''))
    return out


def _pool_size(workers: int, cves: int) -> int:
    if workers:
        return max(1, workers)
    env = os.environ.get('VEX_AUDIT_WORKERS', '')
    if env.isdigit():
        return max(1, int(env))
    if cves < 200:
        return 1
    return max(1, min(8, (os.cpu_count() or 2) - 2))


def _map(work: dict, pool: int):
    """Yield per-CVE results — in forked workers when it is worth it.

    Verdicts are pure CPU; threads would serialise on the GIL.  Fork lets the
    children inherit the prepared rows copy-on-write.
    """
    if pool > 1:
        import multiprocessing as mp
        from concurrent.futures import ProcessPoolExecutor
        try:
            with ProcessPoolExecutor(max_workers=pool,
                                     mp_context=mp.get_context('fork')) as ex:
                yield from ex.map(_audit_cve, work.items(), chunksize=4)
            return
        except (OSError, ValueError, RuntimeError):
            pass                         # no fork here — serial walk below
    for item in work.items():
        yield _audit_cve(item)


# ── input / output shaping ───────────────────────────────────────────────────

def prepare(df: Optional[pd.DataFrame]) -> pd.DataFrame:
    """Normalise a findings frame: advisory ids → CVEs, scanner severity column."""
    if df is None:
        return pd.DataFrame()
    df = resolve_advisory_ids(df)
    if df.empty:
        return df
    df = df.reset_index(drop=True)
    df['RHACS_SEVERITY'] = df['SEVERITY'].map(
        lambda s: SEVERITY_FROM_SCANNER.get(str(s).strip().upper(), 'Unknown'))
    return df


def resolve_advisory_ids(df: pd.DataFrame, console=None) -> pd.DataFrame:
    """Rewrite GHSA/GO ids to the CVE Red Hat publishes VEX under (osv.py).

    The original id stays in ALIAS_ID.  A remapped row that lands on a pair the
    scanner already reported natively is dropped.  OSV_DISABLE=1 turns it off.
    """
    if df is None or df.empty or 'CVE' not in df.columns or os.environ.get('OSV_DISABLE'):
        return df
    from . import osv
    ids = [str(c).strip() for c in df['CVE'].unique() if osv.is_advisory_id(c)]
    mapped = osv.resolve_many(ids) if ids else {}
    if not mapped:
        return df
    if console:
        console.print(f"🔗 {len(mapped)}/{len(ids)} advisory ID(s) resolved to a CVE via OSV")
    if 'ALIAS_ID' not in df.columns:
        df['ALIAS_ID'] = ''
    hit = df['CVE'].isin(mapped)
    df.loc[hit, 'ALIAS_ID'] = df.loc[hit, 'CVE']
    df.loc[hit, 'CVE'] = df.loc[hit, 'CVE'].map(mapped)
    if 'COMPONENT' in df.columns:
        native = set(zip(df.loc[~hit, 'COMPONENT'], df.loc[~hit, 'CVE']))
        collides = hit & pd.Series([p in native for p in zip(df['COMPONENT'], df['CVE'])],
                                   index=df.index)
        if collides.any():
            df = df[~collides].reset_index(drop=True)
    return df


def finalize(df: pd.DataFrame, false_only: bool = False) -> pd.DataFrame:
    """Select the result columns, add FIXABLE, sort, optionally keep only FPs."""
    cols = ['COMPONENT', 'VEX_PRODUCT', 'VERSION', 'CVE', 'SEVERITY', 'AUDIT_RESULT',
            'VEX_FIX_VER', 'JUSTIFICATION', 'VEX_STATE', 'RHACS_SEVERITY',
            'SEVERITY_MISMATCH'] + [c for c in _CARRIED if c in df.columns]
    for col in cols:
        if col not in df.columns:
            df[col] = pd.Series(dtype=str)
    out = df[list(dict.fromkeys(cols))].copy()

    def present(s):
        s = s.fillna('').astype(str).str.strip()
        return (s != '') & (s != 'N/A') & (s != 'nan')
    out['FIXABLE'] = present(out['VEX_FIX_VER']) | present(out['FIXED_VERSION'])
    if len(out):
        def rank(row):
            j, r = str(row['JUSTIFICATION']), str(row['AUDIT_RESULT'])
            if '✅' in r:
                p = 0
            elif 'Under investigation' in j:
                p = 4
            elif 'VEX file missing' in j:
                p = 3
            else:
                p = 2
            sev = _SEVERITY_ORDER.get(str(row.get('SEVERITY', 'Unknown')).split()[0].title()
                                      if str(row.get('SEVERITY', '')).strip() else 'Unknown', 4)
            return p * 100 + sev
        out = out.iloc[out.apply(rank, axis=1).to_numpy().argsort(kind='stable')]
    if false_only:
        out = out[out['AUDIT_RESULT'] == FP]
    return out


# ── how much of a verdict is Red Hat's own claim ─────────────────────────────

# A justification that opens with one of these quotes a real Red Hat statement,
# just one not scoped to this build/product (VEX_STATED stays False).
_STATEMENT_PREFIXES = ('known_not_affected', 'known_affected', 'under_investigation',
                       'No affected entry', 'No supported Red Hat product affected',
                       'Image build', 'This image build', 'Fixed in')


def is_stated(row) -> bool:
    """Red Hat stated this verdict about this product/build (publishable)."""
    return str(row.get('VEX_STATED', '')).strip().lower() in ('true', '1')


def evidence_of(row) -> str:
    """'stated' (about this build), 'other bld' (a real statement about another
    build/release), or 'not listed' (Red Hat's enumeration does not name us)."""
    if is_stated(row):
        return 'stated'
    if str(row.get('JUSTIFICATION', '') or '').lstrip().startswith(_STATEMENT_PREFIXES):
        return 'other bld'
    return 'not listed'
