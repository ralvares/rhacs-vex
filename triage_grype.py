#!/usr/bin/env python3
"""
triage_grype.py — VEX triage for Red Hat / UBI images using grype (+ syft).

Scans a container image locally with grype for CVEs, then cross-references
Red Hat VEX data to identify false positives — no RHACS required.

All scan data stays in memory; nothing is written to disk beyond the VEX JSON
cache (data/vex/) and the optional --output report.

Modes:
  --image IMAGE_REF     Scan a single Red Hat / UBI image and run VEX triage.
  --ocp   PULLSPECS     Triage every component in an OCP release manifest
                        (file produced by: oc adm release info <ver> --pullspecs).

Requires:
  grype ≥ 0.60  (https://github.com/anchore/grype)
  syft          (optional; only for --sbom display mode)

Usage examples:
  python3 triage_grype.py --image registry.access.redhat.com/ubi9/ubi:latest
  python3 triage_grype.py --image quay.io/openshift/origin-cli:latest --false-only
  python3 triage_grype.py --ocp 4.21.2.txt --output data/reports/ocp-4.21.2-grype.csv
  python3 triage_grype.py --image registry.access.redhat.com/ubi8/ubi:latest --sbom
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import pandas as pd
from rich import box
from rich.console import Console
from rich.table import Table

# ── Re-use the entire VEX audit engine + display helpers from triage.py ──────
# Only the RHACS API layer is replaced; everything else is shared.
from triage import (
    WorkloadContext,
    parse_image_ref,
    parse_context_from_labels,
    sbom_to_packages_df,
    _audit_and_display,
    _audit_silent,
    _render_triage_table,
    _write_output,
    _print_sbom_summary,
    RESULT_STYLES,
)

# ── Registry pull-secret state ──────────────────────────────────────────────
# Set once by _init_pull_secret(); injected into every grype/syft subprocess.
_docker_config_env: dict = {}
_pull_secret_tmpdir: Optional[tempfile.TemporaryDirectory] = None


def _init_pull_secret(path: str) -> None:
    """Configure registry auth from a pull secret JSON file.

    Accepts two formats:
      - Raw Docker config JSON : {"auths": {"registry.redhat.io": {"auth": "..."}}}
      - Kubernetes Secret JSON : {"kind": "Secret", "data": {".dockerconfigjson": "<b64>"}}

    Sets DOCKER_CONFIG to a temp directory so grype/syft pick up the
    credentials transparently via the standard Docker credential protocol.
    """
    global _docker_config_env, _pull_secret_tmpdir
    try:
        with open(path) as fh:
            raw = json.load(fh)
    except Exception as exc:
        raise RuntimeError(f"Cannot read pull secret {path!r}: {exc}") from exc

    # Kubernetes Secret format → decode the embedded dockerconfigjson
    if isinstance(raw, dict) and raw.get("kind") == "Secret":
        encoded = (raw.get("data") or {}).get(".dockerconfigjson", "")
        if not encoded:
            raise RuntimeError("Kubernetes Secret has no .dockerconfigjson field")
        docker_cfg = json.loads(base64.b64decode(encoded))
    else:
        docker_cfg = raw  # raw Docker config JSON

    if "auths" not in docker_cfg:
        raise RuntimeError(f"Pull secret does not contain an 'auths' key: {path!r}")

    _pull_secret_tmpdir = tempfile.TemporaryDirectory(prefix="triage_grype_ps_")
    cfg_path = os.path.join(_pull_secret_tmpdir.name, "config.json")
    with open(cfg_path, "w") as fh:
        json.dump(docker_cfg, fh)
    _docker_config_env = {"DOCKER_CONFIG": _pull_secret_tmpdir.name}


# ── SBOM cross-check (dict-based, no RHACS session needed) ──────────────────────

def _verify_sbom_dict(sbom: dict, result_df: pd.DataFrame) -> dict:
    """Cross-check every unique (component, version) in result_df against a syft SBOM.

    Accepts both Syft JSON format (artifacts.packages[]) and SPDX format.
    Returns: {matched, total, mismatched, error}.
    """
    try:
        pkg_versions: dict = {}

        # Syft JSON format: has "artifacts" key with "packages" array
        if "artifacts" in sbom:
            for pkg in sbom.get("artifacts", {}).get("packages", []):
                name = pkg.get("name", "")
                ver = pkg.get("version", "")
                if name:
                    pkg_versions.setdefault(name, set()).add(ver)
        else:
            # SPDX format fallback
            from lib4sbom.parser import SBOMParser as _SBOMParser
            parser = _SBOMParser(sbom_type="spdx")
            parser.parse_string(json.dumps(sbom))
            for pkg in parser.get_packages():
                name = pkg.get("name", "")
                ver = pkg.get("version", "")
                if name:
                    pkg_versions.setdefault(name, set()).add(ver)

        matched, mismatched, seen = 0, [], set()
        for _, row in result_df.iterrows():
            key = (row["COMPONENT"], row["VERSION"])
            if key in seen:
                continue
            seen.add(key)
            comp, ver = key
            ver_clean = ver.split(":", 1)[-1] if ":" in ver else ver
            sbom_vers = pkg_versions.get(comp, set())
            sbom_clean = {v.split(":", 1)[-1] if ":" in v else v for v in sbom_vers}
            if ver_clean in sbom_clean or ver in sbom_vers:
                matched += 1
            else:
                mismatched.append((comp, ver, sorted(sbom_vers)))
        return {"matched": matched, "total": len(seen), "mismatched": mismatched, "error": None}
    except Exception as exc:
        return {"matched": 0, "total": 0, "mismatched": [], "error": str(exc)}


# ── Grype severity → Red Hat display form ─────────────────────────────────────
_GRYPE_SEVERITY_MAP: dict = {
    "critical":   "Critical",
    "high":       "Important",
    "medium":     "Moderate",
    "low":        "Low",
    "negligible": "Low",
    "unknown":    "Unknown",
    "":           "Unknown",
}


# ── Helper utilities ──────────────────────────────────────────────────────────

def _src_name_from_rpm(source_rpm: str) -> str:
    """Extract the source package name from a *.src.rpm filename.

    'openssl-1.1.1k-7.el8_6.src.rpm'       → 'openssl'
    'python-urllib3-1.24.2-5.el8.src.rpm'   → 'python-urllib3'
    """
    base = source_rpm.removesuffix(".src.rpm")
    m = re.search(r"-\d", base)
    return base[: m.start()] if m else base


def _best_cvss(vuln: dict) -> float:
    """Return the highest CVSS base score found in a grype vulnerability dict."""
    best = 0.0
    for score in vuln.get("cvss", []):
        try:
            v = float((score.get("metrics") or {}).get("baseScore") or 0)
        except (TypeError, ValueError):
            v = 0.0
        if v > best:
            best = v
    return best


# ── Grype / Syft subprocess runners ──────────────────────────────────────────

def _run_grype(image_ref: str) -> dict:
    """Generate an SBOM with syft, then feed it to grype via stdin.

    The image is pulled only once by syft.  Grype receives the SPDX JSON
    on stdin (``sbom:-``) so it never pulls the image itself, making
    repeated scans and OCP-release batch runs significantly faster.

    --by-cve maps GHSA/vendor IDs to canonical CVE IDs where a mapping
    exists — critical for java-archive findings which grype otherwise
    reports under GHSA identifiers that the CVE filter drops.

    All data stays in memory; no files are written to disk.
    Raises RuntimeError on non-zero exit of either process.
    """
    env = {
        **os.environ,
        **_docker_config_env,
        # Enable CPE matching for all ecosystems so grype finds vulns in
        # Python/Go/JS packages even when the image distro is RPM-based.
        # Matches harpia's in-process behavior (GenerateMissingCPEs: true).
        "GRYPE_MATCH_PYTHON_USING_CPES": "true",
        "GRYPE_MATCH_GOLANG_USING_CPES": "true",
        "GRYPE_MATCH_JAVASCRIPT_USING_CPES": "true",
        "GRYPE_MATCH_DOTNET_USING_CPES": "true",
        "GRYPE_MATCH_JAVA_USING_CPES": "true",
    }

    # Step 1: syft indexes the image and produces Syft JSON SBOM
    # Using syft-json (not spdx-json) ensures all package types are preserved
    # including Python pip packages that SPDX output may drop.
    syft_proc = subprocess.run(
        ["syft", image_ref, "-o", "syft-json", "--quiet"],
        capture_output=True, env=env,
    )
    if syft_proc.returncode != 0:
        snippet = (syft_proc.stderr or b"").decode().strip()[:400]
        raise RuntimeError(f"syft exited {syft_proc.returncode}: {snippet}")

    syft_sbom = json.loads(syft_proc.stdout)

    # Step 2: grype scans the SBOM — no image pull needed
    grype_proc = subprocess.run(
        ["grype", "-o", "json", "--quiet", "--by-cve", "--add-cpes-if-none"],
        input=syft_proc.stdout, capture_output=True, env=env,
    )
    if grype_proc.returncode != 0:
        snippet = (grype_proc.stderr or b"").decode().strip()[:400]
        raise RuntimeError(f"grype exited {grype_proc.returncode}: {snippet}")

    grype_result = json.loads(grype_proc.stdout)

    # Step 3: grype skips non-distro packages (python/go) in RPM images.
    # Scan them separately via PURL input to match harpia's in-process behavior.
    non_rpm_types = {"python", "go-module", "npm", "gem", "java-archive"}
    purls = []
    for pkg in syft_sbom.get("artifacts", []):
        if pkg.get("type", "") in non_rpm_types and pkg.get("purl"):
            purls.append(pkg["purl"])

    if purls:
        purl_file = os.path.join(tempfile.gettempdir(), "harpia_purls.txt")
        with open(purl_file, "w") as f:
            f.write("\n".join(purls))
        purl_proc = subprocess.run(
            ["grype", f"purl:{purl_file}", "-o", "json", "--quiet", "--by-cve"],
            capture_output=True, env=env,
        )
        if purl_proc.returncode == 0:
            purl_result = json.loads(purl_proc.stdout)
            # Merge: add matches not already found
            existing = {(m["vulnerability"]["id"], m["artifact"]["name"], m["artifact"]["version"])
                       for m in grype_result.get("matches", [])}
            for m in purl_result.get("matches", []):
                key = (m["vulnerability"]["id"], m["artifact"]["name"], m["artifact"]["version"])
                if key not in existing:
                    grype_result["matches"].append(m)
        os.remove(purl_file)

    return grype_result, syft_sbom


def _run_syft(image_ref: str) -> dict:
    """Run syft against *image_ref* and return the parsed SPDX-JSON SBOM.

    stdout is captured entirely in memory — no files are written to disk.
    Raises RuntimeError on non-zero exit.
    """
    cmd = ["syft", image_ref, "-o", "spdx-json", "--quiet"]
    proc = subprocess.run(
        cmd, capture_output=True, text=True,
        env={**os.environ, **_docker_config_env},
    )
    if proc.returncode != 0:
        snippet = (proc.stderr or "").strip()[:400]
        raise RuntimeError(f"syft exited {proc.returncode}: {snippet}")
    return json.loads(proc.stdout)


# ── Data conversion ───────────────────────────────────────────────────────────

def _src_map_from_grype(grype_data: dict) -> dict:
    """Build binary → source RPM name map from grype artifact metadata.

    grype embeds ``sourceRpm`` in every RPM artifact, so we derive the
    source package name directly — no separate syft call needed.

    Example:
      artifact.name='openssl-libs'
      artifact.metadata.sourceRpm='openssl-1.1.1k-7.el8.src.rpm'
      → {'openssl-libs': 'openssl'}
    """
    src_map: dict = {}
    seen: set = set()
    for match in grype_data.get("matches", []):
        artifact = match.get("artifact", {})
        if artifact.get("type", "").lower() != "rpm":
            continue
        bin_name = artifact.get("name", "")
        if not bin_name or bin_name in seen:
            seen.add(bin_name)
            continue
        seen.add(bin_name)
        meta     = artifact.get("metadata") or {}
        src_rpm  = meta.get("sourceRpm") or meta.get("source", "")
        if not src_rpm:
            continue
        src_name = _src_name_from_rpm(src_rpm)
        if src_name and src_name != bin_name:
            src_map[bin_name] = src_name
    return src_map


def grype_to_df(grype_data: dict) -> pd.DataFrame:
    """Flatten a grype JSON report into the standard triage DataFrame schema.

    Only CVE-prefixed identifiers are kept (Red Hat VEX is keyed by CVE ID).
    Duplicate (CVE, component, version) rows are dropped.
    """
    _COLS = ["COMPONENT", "VERSION", "CVE", "SEVERITY", "CVSS",
             "LINK", "FIXED_VERSION", "ADVISORY", "ADVISORY_LINK"]
    rows = []
    seen: set = set()
    for match in grype_data.get("matches", []):
        vuln     = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        cve  = (vuln.get("id") or "").upper().strip()
        if not cve.startswith("CVE-"):
            continue
        comp = artifact.get("name", "")
        ver  = artifact.get("version", "")
        key  = (cve, comp, ver)
        if key in seen:
            continue
        seen.add(key)
        sev_raw   = (vuln.get("severity") or "unknown").lower()
        fix_vers  = (vuln.get("fix") or {}).get("versions") or []
        rows.append({
            "COMPONENT":     comp,
            "VERSION":       ver,
            "CVE":           cve,
            "SEVERITY":      _GRYPE_SEVERITY_MAP.get(sev_raw, "Unknown"),
            "CVSS":          _best_cvss(vuln),
            "LINK":          f"https://access.redhat.com/security/cve/{cve.lower()}",
            "FIXED_VERSION": fix_vers[0] if fix_vers else "",
            "ADVISORY":      "",
            "ADVISORY_LINK": "",
        })
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=_COLS)


def _ctx_from_grype(grype_data: dict, image_ref: str,
                    ocp_ver: Optional[str] = None,
                    comp_name: Optional[str] = None) -> WorkloadContext:
    """Derive a WorkloadContext from the grype report + image reference.

    grype embeds the full Docker image labels at source.target.labels —
    the same ``cpe`` and ``name`` labels that RHACS exposes.  We use
    parse_context_from_labels (identical to the RHACS code path) so that
    namespace/type/RHEL-version detection is authoritative rather than
    relying on image-ref string parsing alone.

    The grype distro block is kept as a last-resort fallback for images
    that carry no labels (e.g. non-Red-Hat base images).
    *ocp_ver* forces OCP workload context (used in --ocp release mode).
    """
    # ── Primary: use Docker image labels (same as RHACS path) ────────────
    labels = (grype_data.get("source") or {}).get("target", {}).get("labels") or {}
    if labels.get("name") or labels.get("cpe"):
        ctx = parse_context_from_labels(labels, image_ref)
    else:
        ctx = parse_image_ref(image_ref)

    # ── Fallback: refine RHEL version from grype distro block ─────────────
    # Only applied when labels did not supply a CPE with an el<N> token.
    distro      = grype_data.get("distro") or {}
    distro_name = (distro.get("name") or "").lower()
    distro_ver  = distro.get("version") or ""
    if not labels.get("cpe") and any(k in distro_name for k in ("red hat", "rhel", "ubi", "enterprise linux")):
        m = re.match(r"^(\d+)", distro_ver)
        if m:
            ctx.rhel_ver = m.group(1)

    if ocp_ver:
        minor_ver         = ".".join(ocp_ver.split(".")[:2])
        ctx.workload_type = "ocp"
        ctx.ocp_ver       = minor_ver
        ctx.display_name  = f"OpenShift {ocp_ver}"
        ctx.extra_prefixes = []
        # Refine RHEL ver from distro name (e.g. "rhel:10.0") or comp_name hint
        os_rhel = re.search(r"(?:rhel|coreos):(\d+)", distro_name)
        if os_rhel:
            ctx.rhel_ver = os_rhel.group(1)
        elif comp_name:
            cn_rhel = re.search(r"(?:rhel-[^-]+-|rhel-)(\d+)$", comp_name)
            if cn_rhel:
                ctx.rhel_ver = cn_rhel.group(1)

    return ctx


# ── Per-image scan + audit pipeline ──────────────────────────────────────────

def _scan_and_audit(image_ref: str,
                    false_only: bool = False,
                    ocp_ver: Optional[str] = None,
                    comp_name: Optional[str] = None) -> dict:
    """Run grype against *image_ref*, derive context, and run VEX audit.

    All data lives in memory — no local scan files are written.

    Returns a result dict for _display_grype_result:
      found     : True | False | None (None = scan error)
      img_ctx   : WorkloadContext
      os_info   : str  (e.g. 'Red Hat Enterprise Linux 9.4')
      result_df : annotated DataFrame or None
      error     : str or None
    """
    try:
        grype_data, syft_sbom = _run_grype(image_ref)
    except Exception as exc:
        return {"found": None, "error": str(exc)}

    ctx = _ctx_from_grype(grype_data, image_ref, ocp_ver, comp_name)

    # Build binary→source RPM map directly from grype artifact metadata
    ctx.sbom_src_map = _src_map_from_grype(grype_data)

    distro  = grype_data.get("distro") or {}
    os_info = f"{distro.get('name', '')} {distro.get('version', '')}".strip()
    img_df  = grype_to_df(grype_data)

    if img_df.empty:
        return {"found": True, "img_ctx": ctx, "os_info": os_info,
                "result_df": None, "syft_sbom": syft_sbom, "error": None}

    result_df = _audit_silent(img_df, ctx, false_only)
    return {"found": True, "img_ctx": ctx, "os_info": os_info,
            "result_df": result_df, "syft_sbom": syft_sbom, "error": None}


# ── Display helper ────────────────────────────────────────────────────────────

def _display_grype_result(console: Console, label: str, res: dict) -> None:
    """Print per-image header, context, and triage table for a grype result."""
    console.rule(f"[bold cyan]{label}[/bold cyan]")
    if res.get("error"):
        console.print(f"[bold red]❌ Error: {res['error']}[/bold red]\n")
        return
    if not res.get("found"):
        console.print("[yellow]⚠  Scan produced no output — skipped[/yellow]\n")
        return

    img_ctx = res["img_ctx"]
    if res.get("os_info"):
        console.print(f"[bold]OS:[/bold] [cyan]{res['os_info']}[/cyan]")
    console.print(
        f"[bold]Context:[/bold] type=[cyan]{img_ctx.workload_type}[/cyan]  "
        f"rhel=[cyan]{img_ctx.rhel_ver}[/cyan]  "
        f"display=[cyan]{img_ctx.display_name}[/cyan]"
    )
    if img_ctx.extra_prefixes:
        console.print(f"[bold]VEX scope:[/bold] {', '.join(img_ctx.extra_prefixes[:6])}")
    console.print()

    result_df = res.get("result_df")
    if result_df is None or result_df.empty:
        console.print("[dim]No CVE findings to display.[/dim]\n")
        return

    _render_triage_table(console, result_df, img_ctx)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "VEX triage for Red Hat / UBI images using grype — no RHACS required.\n"
            "Scan data is kept entirely in memory; only VEX JSON is cached to data/vex/."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--image", default=None, metavar="IMAGE_REF",
        help="Red Hat / UBI container image to scan and triage.",
    )
    parser.add_argument(
        "--ocp", default=None, metavar="PULLSPECS_FILE",
        help=(
            "Path to 'oc adm release info --pullspecs' output. "
            "Triages every unique component image in the release."
        ),
    )
    parser.add_argument(
        "--sbom", action="store_true", default=False,
        help="Show the SPDX SBOM package list for --image (uses syft).",
    )
    parser.add_argument(
        "--output", default=None, metavar="FILE",
        help="Output file path for the triage report.",
    )
    parser.add_argument(
        "--format", default="csv", choices=["table", "csv", "json"],
        dest="output_fmt",
        help="Output format: csv (default), json, or table (terminal only).",
    )
    parser.add_argument(
        "--false-only", action="store_true", default=False,
        help="Only show FALSE POSITIVE findings.",
    )
    parser.add_argument(
        "--workers", type=int, default=4, metavar="N",
        help=(
            "Parallel image workers for --ocp mode (default: 4). "
            "Each grype scan pulls and analyses image layers — keep this modest."
        ),
    )
    parser.add_argument(
        "--pull-secret", default=None, metavar="FILE", dest="pull_secret",
        help=(
            "Path to a registry pull secret JSON file for authenticating against "
            "private registries (e.g. registry.redhat.io). "
            "Accepts raw Docker config format (cloud.redhat.com download) or "
            "Kubernetes Secret format (.dockerconfigjson)."
        ),
    )
    args = parser.parse_args()

    if args.ocp and args.image:
        parser.error("--ocp and --image are mutually exclusive")
    if not args.image and not args.ocp:
        parser.error("Specify --image or --ocp")

    console = Console()

    if args.pull_secret:
        try:
            _init_pull_secret(args.pull_secret)
            console.print(f"[dim]🔑 Pull secret loaded from {args.pull_secret}[/dim]")
        except RuntimeError as exc:
            console.print(f"[bold red]❌ {exc}[/bold red]")
            raise SystemExit(1)

    # syft SBOM fetched once and reused for both --sbom display and cross-check.
    _syft_sbom: Optional[dict] = None

    # ── SBOM mode (syft) ──────────────────────────────────────────────────────
    if args.sbom and args.image:
        console.print(f"\n[bold]Mode:[/bold] [cyan]SBOM (syft)[/cyan]  "
                      f"image=[cyan]{args.image}[/cyan]")
        try:
            console.print(f"📦 Fetching SPDX SBOM via syft for [cyan]{args.image}[/cyan]...")
            sbom    = _run_syft(args.image)
            _syft_sbom = sbom
            pkgs_df = sbom_to_packages_df(sbom)
            created  = (sbom.get("creationInfo") or {}).get("created", "")
            creators = ", ".join((sbom.get("creationInfo") or {}).get("creators", []))
            console.print(f"  SPDX version : [dim]{sbom.get('spdxVersion', '')}[/dim]")
            if created:
                console.print(f"  Created      : [dim]{created}[/dim]")
            if creators:
                console.print(f"  Tools        : [dim]{creators}[/dim]")
            console.print(f"  Packages     : [bold]{len(pkgs_df)}[/bold]")
            console.print()

            tbl = Table(
                title=f"SBOM Packages — [bold cyan]{args.image}[/bold cyan]",
                box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=False,
            )
            tbl.add_column("Package", style="cyan",    no_wrap=True)
            tbl.add_column("Version", style="dim",     no_wrap=False, max_width=40)
            tbl.add_column("Purpose", style="magenta", no_wrap=True)
            tbl.add_column("File",    style="dim",     no_wrap=False, max_width=45)
            for _, row in pkgs_df.iterrows():
                tbl.add_row(row["NAME"], row["VERSION"], row["PURPOSE"], row["FILE"])
            console.print(tbl)
            console.print()
        except Exception as exc:
            console.print(f"[bold red]❌ syft error: {exc}[/bold red]")
            raise SystemExit(1)
        # If --image was also given without --ocp, fall through to triage below.
        # If only --sbom + --image and no output requested, stop here.
        if args.output_fmt == "table" and not args.output:
            raise SystemExit(0)

    # ── OCP release mode ──────────────────────────────────────────────────────
    if args.ocp:
        if not os.path.exists(args.ocp):
            console.print(f"[bold red]❌ Pullspecs file not found: {args.ocp}[/bold red]")
            raise SystemExit(1)

        images: list = []
        seen_digests: set = set()
        _ocp_ver: Optional[str] = None

        with open(args.ocp) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("Pull From:"):
                    continue
                nm = re.match(r"^Name:\s+(\d+\.\d+(?:\.\d+)*)", line)
                if nm and _ocp_ver is None:
                    _ocp_ver = nm.group(1)
                    continue
                m = re.match(r"^(\S+)\s+(\S+@sha256:[a-f0-9]+)", line)
                if not m:
                    continue
                comp_name, image_ref = m.group(1), m.group(2)
                dm = re.search(r"@sha256:([a-f0-9]+)", image_ref)
                digest = dm.group(1) if dm else image_ref
                if digest not in seen_digests:
                    seen_digests.add(digest)
                    images.append((comp_name, image_ref))

        if not images:
            console.print(f"[bold red]❌ No image pull specs found in {args.ocp}[/bold red]")
            console.print("  Make sure the file was created with: "
                          "oc adm release info <version> --pullspecs")
            raise SystemExit(1)

        console.print(
            f"\n[bold]Mode:[/bold] [cyan]OCP release (grype)[/cyan]  "
            f"file=[cyan]{args.ocp}[/cyan]  version=[cyan]{_ocp_ver or '?'}[/cyan]"
        )
        console.print(f"✅ Parsed [bold]{len(images)}[/bold] unique component image(s)")
        console.print(
            f"⚠  Each grype scan pulls and analyses image layers. "
            f"With {args.workers} worker(s) this may take a while."
        )
        console.print()

        total        = len(images)
        results_map: dict = {}

        console.print(
            f"🚀 Scanning {total} images with [bold]{args.workers}[/bold] "
            f"parallel worker(s)...\n"
        )

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            future_to_comp = {
                ex.submit(
                    _scan_and_audit, image_ref, args.false_only, _ocp_ver, comp_name
                ): (comp_name, image_ref)
                for comp_name, image_ref in images
            }
            done = 0
            for future in as_completed(future_to_comp):
                done += 1
                comp_name, image_ref = future_to_comp[future]
                res = future.result()
                results_map[comp_name] = (image_ref, res)
                status = (
                    "✅" if res.get("found") and res.get("result_df") is not None
                    else ("⚠ " if res.get("found") is False else "❌")
                )
                console.print(f"  [{done}/{total}] {status} {comp_name}", highlight=False)

        console.print()

        all_results: list = []
        for comp_name, image_ref in images:
            image_ref_stored, res = results_map.get(
                comp_name, (image_ref, {"found": False})
            )
            _display_grype_result(
                console, f"{comp_name}  [dim]{image_ref_stored}[/dim]", res
            )
            if res.get("found") and res.get("result_df") is not None:
                r = res["result_df"].copy()
                r["OCP_COMPONENT"] = comp_name
                r["IMAGE"]         = image_ref_stored
                all_results.append(r)

        console.rule("[bold]OCP Release Summary[/bold]")
        scanned = sum(1 for _, r in results_map.values() if r.get("found"))
        errors  = [c for c, (_, r) in results_map.items() if r.get("error")]
        console.print(f"  Scanned : [bold]{scanned}[/bold] / {total} component image(s)")
        if errors:
            console.print(f"  Errors  : [red]{len(errors)}[/red] image(s) failed grype scan")
        console.print()

        if all_results:
            combined = pd.concat(all_results, ignore_index=True)
            counts   = combined["AUDIT_RESULT"].value_counts()
            for label, count in counts.items():
                style = RESULT_STYLES.get(str(label), "")
                console.print(
                    f"  [{style}]{label}[/{style}]: [bold]{count}[/bold] across "
                    f"{combined[combined['AUDIT_RESULT'] == label]['OCP_COMPONENT'].nunique()}"
                    f" component(s)"
                )
            console.print()
            if args.output and args.output_fmt != "table":
                _write_output(combined, args.output, args.output_fmt, console)

        raise SystemExit(0)

    # ── Single image mode ─────────────────────────────────────────────────────
    console.print(f"\n[bold]Image:[/bold] {args.image}")
    console.print(f"[bold]Mode:[/bold]  [cyan]grype scan[/cyan]")
    console.print("🔍 Running grype...")

    try:
        grype_data, _syft_sbom = _run_grype(args.image)
    except Exception as exc:
        console.print(f"[bold red]❌ grype error: {exc}[/bold red]")
        raise SystemExit(1)

    ctx = _ctx_from_grype(grype_data, args.image)
    ctx.sbom_src_map = _src_map_from_grype(grype_data)

    distro  = grype_data.get("distro") or {}
    os_info = f"{distro.get('name', '')} {distro.get('version', '')}".strip()
    df      = grype_to_df(grype_data)

    if os_info:
        console.print(f"[bold]OS:[/bold]    [cyan]{os_info}[/cyan]")
    console.print(
        f"[bold]Found:[/bold] [cyan]{len(df)} CVE finding(s)[/cyan] across "
        f"[cyan]{df['COMPONENT'].nunique() if len(df) else 0} component(s)[/cyan]"
    )
    console.print(
        f"[bold]Context:[/bold] type=[cyan]{ctx.workload_type}[/cyan]  "
        f"rhel=[cyan]{ctx.rhel_ver}[/cyan]  display=[cyan]{ctx.display_name}[/cyan]"
    )
    if ctx.extra_prefixes:
        console.print(f"[bold]VEX scope:[/bold] {', '.join(ctx.extra_prefixes[:6])}")
    console.print()

    _out_path = args.output if args.output and args.output_fmt != "table" else None
    result_df = _audit_and_display(
        df, ctx, console,
        output_path=_out_path,
        output_fmt=args.output_fmt,
        false_only=args.false_only,
    )

    # ── SBOM cross-check ─────────────────────────────────────────────────────
    # syft already ran as part of _run_grype above, so _syft_sbom is always
    # available — no second pull or syft invocation needed.
    if result_df is not None and not result_df.empty and _syft_sbom is not None:
        sbom_s = _verify_sbom_dict(_syft_sbom, result_df)
        _print_sbom_summary(console, sbom_s)


if __name__ == "__main__":
    main()
