#!/usr/bin/env python3
"""
triage_operators_clairv4.py — Triage OLM operators using the local StackRox
Scanner V4 (ClairCore) instead of RHACS.

For each OCP catalog version found in data/catalogs/, the tool:
  1. Parses the catalog to find all operator packages.
  2. Identifies the head bundle of each operator's default channel.
  3. Retrieves all workload images from that bundle's relatedImages.
  4. Scans every image with the local Scanner V4 stack (via scannerctl).
  5. Cross-references findings against Red Hat VEX data.
  6. Writes per-operator reports to:
       data/reports/ocp-{version}/{operator}-{channel}-{bundle_version}.csv

No RHACS credentials required — only a running local Scanner V4 stack
(see rhacs-scanner-local/README.md).

Usage examples:
  python3 triage_operators_clairv4.py
  python3 triage_operators_clairv4.py --version 4.21
  python3 triage_operators_clairv4.py --version 4.21 --operator cluster-logging
  python3 triage_operators_clairv4.py --version 4.20,4.21 --workers 2 --skip-existing
  python3 triage_operators_clairv4.py --version 4.21 --pull-secret ~/pullsecret.txt
"""

import argparse
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
from rich.console import Console

# ── Import shared catalog helpers from triage_operators.py ───────────────────
# Nothing in the catalog layer touches RHACS — safe to import directly.
from triage_operators import (
    build_operator_index,
    available_catalog_versions,
    _get_unique_workload_images,
    _report_path,
    _print_version_summary,
    CATALOG_DIR,
    REPORTS_DIR,
)

# ── Import the Scanner V4 scan + audit pipeline from triage_clairv4.py ────────
import triage_clairv4 as tc

console = Console()


# ── Core triage logic (Scanner V4 edition) ───────────────────────────────────

def triage_operator_clairv4(
    bundle: dict,
    false_only: bool = False,
    workers: int = 2,
) -> pd.DataFrame | None:
    """Scan all workload images in *bundle* with Scanner V4 and return a combined
    triage DataFrame, or None if no actionable findings were produced.

    Each row carries the standard triage columns plus:
      IMAGE      — full image reference
      IMAGE_ROLE — the 'name' field from relatedImages (may be empty)
    """
    images = _get_unique_workload_images(bundle)
    if not images:
        return None

    frame_parts: list = []

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(tc._scan_and_audit, img, false_only): (role, img)
            for role, img in images
        }
        for future in as_completed(futures):
            role, img = futures[future]
            try:
                res = future.result()
            except Exception:
                continue
            if not res.get("found") or res.get("result_df") is None:
                continue
            rdf = res["result_df"].copy()
            rdf.insert(0, "IMAGE",      img)
            rdf.insert(1, "IMAGE_ROLE", role)
            frame_parts.append(rdf)

    if not frame_parts:
        return None
    return pd.concat(frame_parts, ignore_index=True)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Triage OLM operators from OCP catalogs using the local Scanner V4 "
            "(ClairCore) — no RHACS required.\n"
            "Writes per-operator CSV reports to data/reports/ocp-{version}/."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--version", default=None, metavar="VERSION",
        help='Comma-separated OCP version(s), e.g. "4.21" or "4.20,4.21". '
             "Defaults to all versions found in data/catalogs/.",
    )
    parser.add_argument(
        "--operator", default=None, metavar="NAME",
        help="Comma-separated operator package name(s) to process. Defaults to all.",
    )
    parser.add_argument(
        "--workers", type=int, default=2, metavar="N",
        help="Parallel image workers per operator (default: 2).",
    )
    parser.add_argument(
        "--false-only", action="store_true", default=False,
        help="Include only FALSE POSITIVE findings in the output CSVs.",
    )
    parser.add_argument(
        "--skip-existing", action="store_true", default=False,
        help="Skip operators whose report CSV already exists (useful for resuming).",
    )
    parser.add_argument(
        "--pull-secret", default=None, metavar="FILE", dest="pull_secret",
        help="Pull-secret file (raw Docker config or Kubernetes Secret JSON) for "
             "private registries. Per-image creds are matched by registry host.",
    )
    parser.add_argument("--auth", default=None, metavar="USER:PASS",
                        help="Single registry basic-auth credential for all images.")
    parser.add_argument("--indexer-address", default=tc.DEFAULT_INDEXER, dest="indexer",
                        help=f"Scanner V4 indexer gRPC address (default: {tc.DEFAULT_INDEXER}).")
    parser.add_argument("--matcher-address", default=tc.DEFAULT_MATCHER, dest="matcher",
                        help=f"Scanner V4 matcher gRPC address (default: {tc.DEFAULT_MATCHER}).")
    parser.add_argument("--scannerctl", default=None, dest="scannerctl_path",
                        help="Path to the scannerctl binary (overrides auto-detection).")
    args = parser.parse_args()

    # Initialise the Scanner V4 client state before any scan is spawned.
    try:
        tc.configure(
            scannerctl=args.scannerctl_path,
            indexer=args.indexer,
            matcher=args.matcher,
            basic_auth=args.auth,
            pull_secret=args.pull_secret,
        )
    except Exception as exc:
        console.print(f"[bold red]❌ {exc}[/bold red]")
        raise SystemExit(1)
    if tc._pull_secret_auths:
        regs = ", ".join(sorted(tc._pull_secret_auths))
        console.print(f"[dim]🔑 pull secret: {len(tc._pull_secret_auths)} registry cred(s) — {regs}[/dim]")
    console.print(f"[dim]scannerctl: {tc._scannerctl}  "
                  f"indexer={tc._indexer_addr} matcher={tc._matcher_addr}[/dim]")

    # Resolve OCP versions to process
    if args.version:
        versions = [v.strip() for v in args.version.split(",") if v.strip()]
    else:
        versions = available_catalog_versions()
    if not versions:
        console.print(f"[bold red]❌ No catalog files found in {CATALOG_DIR}[/bold red]")
        raise SystemExit(1)

    op_filter = {o.strip() for o in args.operator.split(",")} if args.operator else None

    for ocp_ver in versions:
        cat_path = os.path.join(CATALOG_DIR, f"catalog-{ocp_ver}.json")
        if not os.path.exists(cat_path):
            console.print(f"[yellow]⚠  Catalog not found for OCP {ocp_ver}: {cat_path}[/yellow]")
            continue

        console.rule(f"[bold cyan]OCP {ocp_ver}[/bold cyan]")
        console.print(f"📂 Parsing [cyan]{cat_path}[/cyan] ...")
        op_index = build_operator_index(cat_path)
        total_channels = sum(len(v) for v in op_index.values())
        console.print(f"   {len(op_index)} operators, {total_channels} channels in catalog.")

        operators = {
            k: v for k, v in op_index.items()
            if op_filter is None or k in op_filter
        }
        if not operators:
            console.print("[yellow]  No matching operators.[/yellow]")
            continue

        summary_rows: list = []

        for op_name, ch_entries in operators.items():
            for ch_entry in ch_entries:
                channel     = ch_entry["channel"]
                is_default  = ch_entry["is_default"]
                bundle      = ch_entry["head_bundle"]
                bundle_name = bundle.get("name", "")

                _vm = re.search(r"\.v(\d)", bundle_name)
                if _vm:
                    bundle_version = bundle_name[_vm.start(0) + 1:]
                elif bundle_name.startswith(op_name + "."):
                    bundle_version = bundle_name[len(op_name) + 1:]
                else:
                    bundle_version = bundle_name

                report_path = _report_path(ocp_ver, op_name, channel, bundle_version)
                default_tag = " [dim](default)[/dim]" if is_default else ""

                if args.skip_existing and os.path.exists(report_path):
                    console.print(
                        f"  [dim]━ {op_name} / {channel} {bundle_version} — skipped (exists)[/dim]"
                    )
                    continue

                images = _get_unique_workload_images(bundle)
                console.print(
                    f"\n  [bold]{op_name}[/bold] / [cyan]{channel}[/cyan]{default_tag} "
                    f"[dim]{bundle_version}[/dim] — [cyan]{len(images)}[/cyan] image(s)"
                )

                if not images:
                    console.print("    [dim]No workload images in this bundle.[/dim]")
                    summary_rows.append({
                        "operator": op_name, "channel": channel,
                        "bundle_version": bundle_version,
                        "images": 0, "vulnerable": 0, "false_positive": 0,
                        "skipped": True, "report": "",
                    })
                    continue

                t0 = time.time()
                df = triage_operator_clairv4(bundle,
                                             false_only=args.false_only,
                                             workers=args.workers)
                elapsed = time.time() - t0

                if df is None or df.empty:
                    console.print(f"    [dim]No findings from Scanner V4. ({elapsed:.1f}s)[/dim]")
                    summary_rows.append({
                        "operator": op_name, "channel": channel,
                        "bundle_version": bundle_version,
                        "images": len(images), "vulnerable": 0, "false_positive": 0,
                        "skipped": False, "report": "",
                    })
                    continue

                df.to_csv(report_path, index=False)

                counts       = df["AUDIT_RESULT"].value_counts().to_dict()
                n_vuln       = counts.get("❌ POSITIVE", 0)
                n_fp         = counts.get("✅ FALSE POSITIVE", 0)
                n_imgs_found = df["IMAGE"].nunique()

                if args.false_only:
                    console.print(
                        f"    [bold green]✅ {n_fp}[/bold green] false-positive  "
                        f"({n_imgs_found}/{len(images)} images scanned)  "
                        f"→ [cyan]{report_path}[/cyan]  [dim]({elapsed:.1f}s)[/dim]"
                    )
                else:
                    console.print(
                        f"    [bold green]✅ {n_fp}[/bold green] false-positive  "
                        f"[bold red]❌ {n_vuln}[/bold red] positive  "
                        f"({n_imgs_found}/{len(images)} images scanned)  "
                        f"→ [cyan]{report_path}[/cyan]  [dim]({elapsed:.1f}s)[/dim]"
                    )
                summary_rows.append({
                    "operator": op_name, "channel": channel,
                    "bundle_version": bundle_version,
                    "images": len(images), "vulnerable": n_vuln,
                    "false_positive": n_fp, "skipped": False, "report": report_path,
                })

        console.print()
        if summary_rows:
            _print_version_summary(ocp_ver, summary_rows, false_only=args.false_only)

    console.print("\n[bold green]Done.[/bold green]")


if __name__ == "__main__":
    main()
