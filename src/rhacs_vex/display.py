"""Terminal and file output for triage results — rendering only, no decisions."""
from __future__ import annotations

import json
import re
import pandas as pd
from rich.console import Console

from .audit import evidence_of


RESULT_STYLES = {
    "✅ FALSE POSITIVE": "bold green",
    "❌ POSITIVE":       "bold red",
}


SEVERITY_STYLES = {
    "Critical":  "bold red",
    "Important": "red",
    "Moderate":  "yellow",
    "Low":       "dim green",
    "Unknown":   "dim",
}


_SCOPE_NOTE = {
    'other bld': 'other build',
    'not listed': 'not listed',
}


_TYPES = {'OS': 'rpm', 'GO': 'go', 'PYTHON': 'python', 'JAVA': 'java',
          'NODEJS': 'npm', 'RUBY': 'gem', 'IMAGE': 'image'}


def redhat_says(row) -> str:
    """What Red Hat says, in Red Hat's own vocabulary, qualified by scope.

    The State column already carries Red Hat's CVE-page wording (Affected, Not
    affected, Fixed, Will not fix, Fix deferred, Out of support scope).  What was
    missing is WHO it is about, which used to live in a second column of
    abstract words.  Folding the qualifier in keeps one column and one reading:
    an unqualified value is Red Hat's verdict on THIS build; anything in
    parentheses is not.
    """
    state = str(row.get('VEX_STATE', '') or '').strip() or '-'
    ev = evidence_of(row)
    note = _SCOPE_NOTE.get(ev)
    return f'{state} ({note})' if note else state


def type_cell(row) -> str:
    """Which ecosystem the finding came from — rpm, go, python, image."""
    src = str(row.get('SOURCE', '') or '').strip().upper()
    return _TYPES.get(src, src.lower())


def print_preamble(console, *, image_ref: str = '', mode: str = '',
                   os_info: str = '', df=None, ctx=None,
                   noun: str = 'CVE findings') -> None:
    """The header every scan path prints, so only the findings differ.

    A scanner decides WHICH rows exist; everything around them — the image, the
    OS the scanner read, how many components carry findings, the workload
    context and the VEX scope that context resolves to — is the engine's, and
    reads the same whichever scanner supplied the rows.
    """
    if image_ref:
        console.print(f"\n[bold]Image:[/bold] [cyan]{image_ref}[/cyan]")
    if mode:
        console.print(f"[bold]Mode:[/bold] [cyan]{mode}[/cyan]")
    if os_info:
        console.print(f"[bold]OS:[/bold] [cyan]{os_info}[/cyan]")
    if df is not None:
        comps = df['COMPONENT'].nunique() if len(df) else 0
        console.print(f"[bold]Found:[/bold] [cyan]{len(df):,} {noun}[/cyan] across "
                      f"[cyan]{comps:,} components[/cyan]")
    if ctx is not None:
        console.print(f"[bold]Context:[/bold] type=[cyan]{ctx.workload_type}[/cyan]  "
                      f"rhel=[cyan]{ctx.rhel_ver}[/cyan]  "
                      f"display=[cyan]{ctx.display_name}[/cyan]")
        if getattr(ctx, 'extra_prefixes', None):
            console.print(f"[bold]VEX scope:[/bold] {', '.join(ctx.extra_prefixes[:6])}")
    console.print()


def render_table(console: Console, result_df: pd.DataFrame, ctx,
                 actionable_only: bool = False, candidates: bool = False) -> None:
    """Render a compact box table: POSITIVE first, RHACS vs VEX severity, footer."""
    _vstyle = {'POSITIVE': 'bold red', 'FALSE POSITIVE': 'bold green'}
    _sev_rank = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3, 'Unknown': 4}

    rows = []
    for _, row in result_df.iterrows():
        verdict = str(row['AUDIT_RESULT'])
        verdict_plain = 'FALSE POSITIVE' if 'FALSE' in verdict else 'POSITIVE'
        verdict_mark = 'FP' if verdict_plain == 'FALSE POSITIVE' else 'P'
        fix = str(row.get('VEX_FIX_VER', '') or '')
        rows.append({
            'cve': str(row['CVE']),
            'comp': str(row.get('COMPONENT', '')),
            'type': type_cell(row),
            'rhacs': str(row.get('RHACS_SEVERITY', 'Unknown')),
            'vex': str(row.get('SEVERITY', 'Unknown')),
            'verdict': verdict_mark,
            'verdict_plain': verdict_plain,
            'state': redhat_says(row),
            'fix': fix if fix not in ('', 'N/A', 'nan') else '-',
            'just': str(row['JUSTIFICATION']),
        })
    shown = [r for r in rows if r['verdict_plain'] == 'POSITIVE'] if actionable_only else rows
    hidden = len(rows) - len(shown)
    rows_all, rows = rows, shown
    rows.sort(key=lambda r: (
        0 if r['verdict_plain'] == 'POSITIVE' else 1,
        _sev_rank.get(r['vex'], 9),
        _sev_rank.get(r['rhacs'], 9),
        r['cve'],
    ))

    # Small terminals: drop columns that carry no information for this run
    # (scan-free has no scanner severity at all), then drop the least useful
    # ones until the table fits.  Justification takes whatever is left.
    def _uniform(key, *dead):
        vals = {r[key] for r in rows}
        return not vals or vals <= set(dead)

    columns = [
        ('CVE',          'cve',      18),
        ('Component',    'comp',     None),   # never truncate identities
        ('Type',         'type',     7),
        ('Scan Sev',     'rhacs',    10),
        ('VEX Sev',      'vex',      10),
        ('Verdict',      'verdict',  7),
        ('Red Hat says', 'state',    30),
        ('Fix',          'fix',      18),
        ('Why',          'just',     46),
    ]
    if _uniform('rhacs', 'Unknown', '-', ''):
        columns = [c for c in columns if c[1] != 'rhacs']
    if _uniform('fix', '-', ''):
        columns = [c for c in columns if c[1] != 'fix']
    if _uniform('vex', 'Unknown', '-', ''):
        columns = [c for c in columns if c[1] != 'vex']
    if _uniform('type', ''):
        columns = [c for c in columns if c[1] != 'type']

    def _measure(cols):
        w = [max(len(h), min(max((len(r[k]) for r in rows), default=0), cap)
                 if cap else max((len(r[k]) for r in rows), default=0))
             for h, k, cap in cols]
        return w, sum(w) + 3 * len(cols) + 1

    avail = max(60, getattr(console, 'width', 120) or 120)
    widths, total = _measure(columns)

    # Squeeze the free-text column BEFORE sacrificing any structured one: State
    # is what says WHAT Red Hat claimed (Fixed / Not affected / Will not fix),
    # and RH evidence only says who claimed it — dropping State to keep prose
    # would remove the more informative half.
    if total > avail:
        slack = total - avail
        columns = [(h, k, (max(24, (cap or 40) - slack) if k == 'just' else cap))
                   for h, k, cap in columns]
        widths, total = _measure(columns)
    for droppable in ('rhacs', 'vex', 'fix', 'just', 'state', 'type'):
        if total <= avail:
            break
        if any(c[1] == droppable for c in columns) and len(columns) > 4:
            columns = [c for c in columns if c[1] != droppable]
            widths, total = _measure(columns)

    def cell(text, w):
        return (text[:w - 1] + '…') if len(text) > w else text.ljust(w)

    def style_for(key, r):
        if key in ('rhacs', 'vex'):
            return SEVERITY_STYLES.get(r[key], 'dim')
        if key == 'verdict':
            return _vstyle[r['verdict_plain']]
        if key == 'comp':
            return 'cyan'
        if key == 'fix':
            return 'dim'
        return ''

    top = '┌─' + '─┬─'.join('─' * w for w in widths) + '─┐'
    mid = '├─' + '─┼─'.join('─' * w for w in widths) + '─┤'
    bot = '└─' + '─┴─'.join('─' * w for w in widths) + '─┘'

    if not rows:
        console.print('[green]Nothing to act on — no open findings.[/green]')
    console.print(top, markup=False, soft_wrap=True) if rows else None
    hdr = '│ ' + ' │ '.join(cell(h, w) for (h, _, _), w in zip(columns, widths)) + ' │'
    console.print(f"[bold]{hdr}[/bold]", soft_wrap=True)
    console.print(mid, markup=False, soft_wrap=True)
    for r in rows:
        parts = []
        for (_, key, _), w in zip(columns, widths):
            text = cell(r[key], w)
            st = style_for(key, r)
            parts.append(f"[{st}]{text}[/{st}]" if st else text)
        console.print('│ ' + ' │ '.join(parts) + ' │', soft_wrap=True)
    console.print(bot, markup=False, soft_wrap=True)

    total = len(rows_all)
    if not total:
        return
    fp  = sum(1 for r in rows_all if r['verdict_plain'] == 'FALSE POSITIVE')
    pos = sum(1 for r in rows_all if r['verdict_plain'] == 'POSITIVE')

    sev_shift = sum(1 for r in rows_all if r['rhacs'] not in ('Unknown', r['vex']))

    label = ctx.image_ref or ctx.display_name
    m = re.search(r'@sha256:([a-f0-9]{6})', label or '')
    if m:
        label = re.sub(r'@sha256:[a-f0-9]+', f" (sha256:{m.group(1)}...)", label)
    console.print(f"\nImage: [bold cyan]{label}[/bold cyan]")
    # A scanner hands over findings, so clearing one is calling it a false
    # positive.  The index hands over every pair the corpus COULD decide, most of
    # which were never claims about this image — calling those false positives
    # invents a scanner that never reported them.
    if candidates:
        console.print(
            f"[bold]{total}[/bold] candidates checked → [bold red]{pos} findings"
            f"[/bold red]; {fp} not a match for this image."
        )
    else:
        console.print(
            f"[bold]{total}[/bold] findings → [bold green]{fp} false positives[/bold green] "
            f"({100 * fp // total}%), [bold red]{pos} real[/bold red]."
        )
    if hidden:
        what = 'non-matching' if candidates else 'false positive'
        console.print(f"  [dim]{hidden} {what} row(s) hidden — --false-only to see "
                      f"them, --all-rows for everything; exports always contain all rows.[/dim]")
    if sev_shift:
        console.print(f"[yellow]{sev_shift} finding(s) rated differently by Red Hat VEX than by the scanner.[/yellow]")
    console.print()


def verify_versions(result_df: pd.DataFrame, pkg_versions: dict) -> dict:
    """Cross-check every component+version in result_df against a package list.

    What this proves depends entirely on where *pkg_versions* came from, and the
    two callers are not equally strong.  RHACS reports its findings from one
    place and serves the SPDX SBOM from another, so agreement is corroboration.
    On the scanner paths the package list and the findings both descend from the
    same syft catalogue, so agreement only shows that the adapter and the
    scanner report what syft found — worth checking, since epoch handling and
    purl normalisation are exactly where a version quietly changes shape, but it
    is not independent evidence about the image.
    """
    try:
        matched, mismatched, seen = 0, [], set()
        for _, row in result_df.iterrows():
            key = (row["COMPONENT"], row["VERSION"])
            if key in seen:
                continue
            seen.add(key)
            comp, ver = key
            ver_clean  = ver.split(":", 1)[-1] if ":" in ver else ver
            sbom_vers  = pkg_versions.get(comp, set())
            sbom_clean = {v.split(":", 1)[-1] if ":" in v else v for v in sbom_vers}
            if ver_clean in sbom_clean or ver in sbom_vers:
                matched += 1
            else:
                mismatched.append((comp, ver, sorted(sbom_vers)))
        return {"matched": matched, "total": len(seen), "mismatched": mismatched, "error": None}
    except Exception as exc:
        return {"matched": 0, "total": 0, "mismatched": [], "error": str(exc)}


def print_sbom_summary(console: Console, sbom_s: dict) -> None:
    """Print a one-line SBOM verification summary (or per-component warnings)."""
    if sbom_s.get("error"):
        console.print(f"  [dim]SBOM verification skipped: {sbom_s['error']}[/dim]")
        return
    matched, total = sbom_s["matched"], sbom_s["total"]
    mismatched = sbom_s.get("mismatched", [])
    if total == 0:
        return
    if not mismatched:
        console.print(f"  🔍 SBOM verified: [bold green]{matched}/{total}[/bold green] "
                      f"component versions confirmed in image\n")
    else:
        console.print(f"  🔍 SBOM verified: [bold green]{matched}/{total}[/bold green] matched — "
                      f"[bold yellow]{len(mismatched)}[/bold yellow] version(s) not found in SBOM:")
        for comp, ver, sbom_vers in mismatched:
            sbom_str = f"SBOM has: {', '.join(sbom_vers[:2])}" if sbom_vers else "not present in SBOM"
            console.print(f"    [yellow]⚠  {comp} {ver}[/yellow]  [dim]({sbom_str})[/dim]")
        console.print()


def write_output(df: pd.DataFrame, path: str, fmt: str, console: Console) -> None:
    """Write triage results to *path* in the requested format (csv or json)."""
    if fmt == "json":
        with open(path, "w") as fh:
            json.dump(df.to_dict(orient="records"), fh, indent=2, default=str)
    else:
        df.to_csv(path, index=False)
    console.print(f"  Report saved to [cyan]{path}[/cyan] [dim]({fmt})[/dim]\n")


def image_result(console: Console, label: str, res: dict, actionable_only: bool = True) -> None:
    """Per-image block of a batch run: header, context, table, SBOM check."""
    console.rule(f"[bold cyan]{label}[/bold cyan]")
    if res.get("error"):
        console.print(f"[bold red]❌ Error: {res['error']}[/bold red]\n")
        return
    if not res.get("found"):
        console.print("[yellow]⚠  Not found in RHACS — skipped[/yellow]\n")
        return
    print_preamble(console, os_info=res.get('os_info', ''), ctx=res['ctx'])
    result_df = res.get("result_df")
    if result_df is None or result_df.empty:
        console.print("[dim]No findings to display.[/dim]\n")
        return
    render_table(console, result_df, res['ctx'], actionable_only=actionable_only)
    if res.get("sbom_check"):
        print_sbom_summary(console, res["sbom_check"])
