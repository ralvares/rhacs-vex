"""Scan → triage flows shared by every command.

    triage_one(df, ctx, …)        audit + render + export one image's findings
    rhacs_image(central, ref, …)  RHACS scan → enriched findings → verdicts
    rhacs_batch(central, items)   the same over many images, with one retry

Whatever proposed the findings (RHACS, grype, trivy, the VEX index), they go
through the same enrichment (owning rpm, source rpm, SBOM versions) and the
same engine, so a finding gets the same verdict whichever path found it.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import requests

from . import display, scanfree
from .adapters import rhacs
from .audit import audit_frame
from .sbom import SyftSBOM


def triage_one(df, ctx, console, *, output: Optional[str] = None, fmt: str = 'csv',
               false_only: bool = False, show_all: bool = False, candidates: bool = False):
    """Audit one image's findings, print the table, optionally write the file.

    The terminal shows what needs action; false positives are counted in the
    footer (--false-only flips that, --all-rows shows both).  Files keep all rows.
    """
    if df is None or df.empty:
        console.print("[yellow]⚠  No CVE findings to audit.[/yellow]")
        return audit_frame(df, ctx)
    result = audit_frame(df, ctx, false_only=false_only)
    display.render_table(console, result, ctx,
                         actionable_only=not (false_only or show_all), candidates=candidates)
    if output and fmt != 'table':
        display.write_output(result, output, fmt, console)
    return result


def merge_index(df, index, image_ref: str, labels):
    """Add the VEX-index candidates (rpm + image) when an index is given."""
    if index is None:
        return df, 0
    return scanfree.merge_index_candidates(df, index, image_ref=image_ref, labels=labels)


def rhacs_image(central: rhacs.Central, image_ref: str, *, image_id: Optional[str] = None,
                ocp_release: Optional[str] = None, component: Optional[str] = None,
                index: Optional[dict] = None, force: bool = False,
                false_only: bool = False) -> dict:
    """One RHACS image end to end.

    Returns {found, ctx, os_info, result_df, sbom_check, error}; found is False
    when RHACS (or, offline, the cache) has no scan, None on an error.
    """
    try:
        data = (central.image(image_id, image_ref, force=force) if image_id
                else central.scan(image_ref, force=force))
        if not data:
            return {'found': False, 'error': None}
        ctx = rhacs.context_for_scan(image_ref, data, ocp_release=ocp_release,
                                     ocp_component=component)
        spdx = None
        try:
            spdx = central.sbom(image_ref, force=force)
        except Exception:
            pass
        if spdx:
            ctx.sbom_src_map = rhacs.spdx_source_rpms(spdx)
            ctx.sbom_packages = rhacs.spdx_packages(spdx)

        df, _added = merge_index(rhacs.scan_to_df(data), index, image_ref,
                                 rhacs.labels_of(data))
        out = {'found': True, 'ctx': ctx, 'os_info': rhacs.os_of(data),
               'result_df': None, 'sbom_check': None, 'error': None}
        if df.empty:
            return out
        syft = SyftSBOM.for_image(image_ref)      # owning rpm of Go binaries, if cached
        if syft:
            syft.enrich(df, ctx)
        out['result_df'] = audit_frame(df, ctx, false_only=false_only)
        if ctx.sbom_packages:
            out['sbom_check'] = display.verify_versions(out['result_df'], ctx.sbom_packages)
        return out
    except requests.RequestException as e:
        return {'found': None, 'error': str(e)}
    except Exception as e:
        return {'found': None, 'error': f'{type(e).__name__}: {e}'}


def rhacs_batch(central: rhacs.Central, items: list, *, workers: int = 10, console=None,
                **kw) -> dict:
    """rhacs_image over [(key, image_ref, image_id, component)], errors retried once."""
    results = {}

    def run(batch, force, tag):
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(rhacs_image, central, ref, image_id=iid, component=comp,
                              **{**kw, 'force': kw.get('force') or force}): key
                    for key, ref, iid, comp in batch}
            for n, fut in enumerate(as_completed(futs), 1):
                key = futs[fut]
                res = results[key] = fut.result()
                if console:
                    mark = '✅' if res.get('found') else ('⚠ ' if res.get('found') is False else '❌')
                    err = f"  [red]{res['error'][:80]}[/red]" if res.get('error') else ''
                    console.print(f"  [{tag}{n}/{len(batch)}] {mark} {key}{err}", highlight=False)

    run(items, False, '')
    failed = [it for it in items if results[it[0]].get('found') is None]
    if failed and not central.offline:
        if console:
            console.print(f"\n[yellow]⚠  {len(failed)} image(s) failed — retrying...[/yellow]")
        time.sleep(5)
        run(failed, True, 'retry ')
    return results
