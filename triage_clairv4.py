#!/usr/bin/env python3
"""
triage_clairv4.py — VEX triage for Red Hat / UBI images using the **local**
StackRox Scanner V4 (ClairCore) instead of RHACS.

Scans a container image with a locally-running Scanner V4 stack (see
./rhacs-scanner-local/), then cross-references Red Hat VEX data to identify
false positives — no RHACS / Central required.

The entire VEX audit engine and display layer are reused unchanged from
triage.py; only the scanner data source is swapped (RHACS API → local
Scanner V4 via the `scannerctl` CLI).

Modes:
  --image IMAGE_REF     Scan a single image and run VEX triage.
  --ocp   PULLSPECS     Triage every component in an OCP release manifest
                        (file produced by: oc adm release info <ver> --pullspecs).

Requires:
  - A running local Scanner V4 stack (default gRPC at localhost:8443).
    See rhacs-scanner-local/README.md to bring it up.
  - The `scannerctl` binary. Auto-located at ./rhacs-scanner-local/scannerctl,
    or set the SCANNERCTL environment variable, or put it on PATH.

Usage examples:
  python3 triage_clairv4.py --image registry.access.redhat.com/ubi9/ubi:latest
  python3 triage_clairv4.py --image quay.io/openshift/origin-cli:latest --false-only
  python3 triage_clairv4.py --ocp 4.21.2.txt --output data/reports/ocp-4.21.2-clair.csv
  python3 triage_clairv4.py --image registry.access.redhat.com/ubi8/ubi:latest --sbom
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from shutil import which
from typing import Optional

import pandas as pd
from rich import box
from rich.console import Console
from rich.table import Table

# ── Re-use the entire VEX audit engine + display helpers from triage.py ──────
# Only the scanner layer (RHACS → local Scanner V4) is replaced.
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

# ── Scanner V4 connection defaults ───────────────────────────────────────────
DEFAULT_INDEXER = os.environ.get("SCANNER_V4_INDEXER", "localhost:8443")
DEFAULT_MATCHER = os.environ.get("SCANNER_V4_MATCHER", "localhost:8443")

# Registry basic-auth (user:pass), injected as ROX_SCANNERCTL_BASIC_AUTH.
# Explicit --auth, if given, overrides everything (used for all registries).
_basic_auth: Optional[str] = None
# Per-registry creds parsed from a pull secret: {registry_host: "user:pass"}.
_pull_secret_auths: dict = {}
# Resolved scannerctl path / endpoints, set in main().
_scannerctl: Optional[str] = None
_indexer_addr: str = DEFAULT_INDEXER
_matcher_addr: str = DEFAULT_MATCHER


# ── Registry auth: pull-secret parsing ────────────────────────────────────────

def _registry_host(key: str) -> str:
    """Normalise a docker-config auth key (or image ref) to a bare registry host.

    'https://registry.redhat.io/v1/' → 'registry.redhat.io'
    'https://index.docker.io/v1/'    → 'docker.io'
    'quay.io/org/img:tag'            → 'quay.io'
    """
    k = re.sub(r"^https?://", "", key).split("/")[0]
    if "index.docker.io" in k or k == "docker.io":
        return "docker.io"
    return k


def _registry_of_image(image_ref: str) -> str:
    """Extract the registry host an image reference points at."""
    ref = re.sub(r"^https?://", "", image_ref)
    first = ref.split("/")[0]
    if "." in first or ":" in first or first == "localhost":
        return _registry_host(first)
    return "docker.io"  # bare 'library/nginx' style


def _load_pull_secret(path: str) -> dict:
    """Parse a pull-secret file into {registry_host: 'user:pass'}.

    Accepts both raw Docker config JSON ({"auths": {...}}) and Kubernetes Secret
    JSON ({"kind":"Secret","data":{".dockerconfigjson":"<b64>"}}). Each registry's
    creds come from the base64 'auth' field, or explicit username/password fields.
    """
    with open(path) as fh:
        raw = json.load(fh)

    if isinstance(raw, dict) and raw.get("kind") == "Secret":
        encoded = (raw.get("data") or {}).get(".dockerconfigjson", "")
        if not encoded:
            raise RuntimeError("Kubernetes Secret has no .dockerconfigjson field")
        cfg = json.loads(base64.b64decode(encoded))
    else:
        cfg = raw

    auths = cfg.get("auths")
    if not isinstance(auths, dict):
        raise RuntimeError(f"pull secret has no 'auths' object: {path!r}")

    out: dict = {}
    for registry, entry in auths.items():
        entry = entry or {}
        cred = ""
        if entry.get("auth"):
            try:
                cred = base64.b64decode(entry["auth"]).decode("utf-8", "replace")
            except Exception:
                cred = ""
        if not cred and entry.get("username") is not None:
            cred = f'{entry.get("username", "")}:{entry.get("password", "")}'
        if ":" in cred:
            out[_registry_host(registry)] = cred
    return out


def _auth_for_image(image_ref: str) -> Optional[str]:
    """Resolve the basic-auth cred for an image: explicit --auth wins, else pull secret."""
    if _basic_auth:
        return _basic_auth
    host = _registry_of_image(image_ref)
    if host in _pull_secret_auths:
        return _pull_secret_auths[host]
    for reg, cred in _pull_secret_auths.items():
        if host == reg or host.endswith("." + reg) or reg.endswith("." + host):
            return cred
    return None


# ── Module configuration ──────────────────────────────────────────────────────

def configure(*, scannerctl: Optional[str] = None,
              indexer: str = DEFAULT_INDEXER,
              matcher: str = DEFAULT_MATCHER,
              basic_auth: Optional[str] = None,
              pull_secret: Optional[str] = None) -> None:
    """Initialise module state used by the scan/sbom functions.

    Both main() and external callers (e.g. triage_operators_clairv4.py) call this
    before invoking _scan_and_audit / _scan_image so the scannerctl path, gRPC
    endpoints and registry credentials are resolved. Raises RuntimeError if
    scannerctl can't be located or the pull secret can't be parsed.
    """
    global _scannerctl, _indexer_addr, _matcher_addr, _basic_auth, _pull_secret_auths
    _scannerctl = scannerctl or _find_scannerctl()
    _indexer_addr = indexer
    _matcher_addr = matcher
    _basic_auth = basic_auth
    _pull_secret_auths = _load_pull_secret(pull_secret) if pull_secret else {}


# ── scannerctl locator ────────────────────────────────────────────────────────

def _find_scannerctl() -> str:
    """Locate the scannerctl binary: $SCANNERCTL, then ./rhacs-scanner-local/, then PATH."""
    env = os.environ.get("SCANNERCTL")
    if env:
        if os.path.exists(env):
            return env
        raise RuntimeError(f"SCANNERCTL={env!r} does not exist")
    here = Path(__file__).resolve().parent
    local = here / "rhacs-scanner-local" / "scannerctl"
    if local.exists():
        return str(local)
    found = which("scannerctl")
    if found:
        return found
    raise RuntimeError(
        "scannerctl not found. Build it (see rhacs-scanner-local/README.md) "
        "or set the SCANNERCTL environment variable to its path."
    )


# ── Severity mapping ──────────────────────────────────────────────────────────
# Scanner V4 normalized_severity enum → Red Hat display form. scannerctl marshals
# the report with encoding/json, so the enum arrives as an INTEGER (0..4). We also
# accept the string enum name defensively.
_NORM_SEV_INT: dict = {0: "Unknown", 1: "Low", 2: "Moderate", 3: "Important", 4: "Critical"}
_NORM_SEV_STR: dict = {
    "SEVERITY_UNSPECIFIED": "Unknown",
    "SEVERITY_LOW": "Low",
    "SEVERITY_MODERATE": "Moderate",
    "SEVERITY_IMPORTANT": "Important",
    "SEVERITY_CRITICAL": "Critical",
}


def _normalized_severity(vuln: dict) -> str:
    raw = vuln.get("normalized_severity", 0)
    if isinstance(raw, str):
        if raw.isdigit():
            return _NORM_SEV_INT.get(int(raw), "Unknown")
        return _NORM_SEV_STR.get(raw, "Unknown")
    try:
        return _NORM_SEV_INT.get(int(raw), "Unknown")
    except (TypeError, ValueError):
        return "Unknown"


def _best_cvss(vuln: dict) -> float:
    """Highest CVSS base score across cvss_metrics[].v3/.v2 (ignores deprecated scalar)."""
    best = 0.0
    for metric in vuln.get("cvss_metrics", []) or []:
        for key in ("v3", "v2"):
            block = metric.get(key) or {}
            try:
                v = float(block.get("base_score") or 0)
            except (TypeError, ValueError):
                v = 0.0
            if v > best:
                best = v
    return best


# ── progress spinner ──────────────────────────────────────────────────────────

def _with_spinner(console: Console, message: str, fn, *args, **kwargs):
    """Run blocking *fn* while showing a spinner with a live elapsed-time counter.

    The first scan of an image pulls and indexes all layers inside the scanner
    container (network-bound), so this can take minutes — the counter makes it
    clear work is happening rather than hung.
    """
    import threading
    import time as _time

    result, error, done = [None], [None], threading.Event()

    def _runner():
        try:
            result[0] = fn(*args, **kwargs)
        except Exception as exc:  # propagate to caller
            error[0] = exc
        finally:
            done.set()

    th = threading.Thread(target=_runner, daemon=True)
    start = _time.monotonic()
    th.start()
    with console.status(f"[bold]{message}[/bold]", spinner="dots") as status:
        while not done.wait(timeout=1.0):
            status.update(f"[bold]{message}[/bold]  [dim]({int(_time.monotonic() - start)}s)[/dim]")
    th.join()
    if error[0] is not None:
        raise error[0]
    return result[0]


# ── scannerctl subprocess runners ─────────────────────────────────────────────

def _image_url(image_ref: str) -> str:
    """scannerctl requires an http(s):// URL; default to https for bare refs."""
    if image_ref.startswith(("http://", "https://")):
        return image_ref
    return "https://" + image_ref


def _run_scannerctl(subcmd: str, image_ref: str, extra: Optional[list] = None) -> dict:
    """Run `scannerctl <subcmd> <url> ...` and return parsed JSON from stdout.

    scannerctl writes progress/log lines to stderr and the JSON document to
    stdout, so stdout parses cleanly. Raises RuntimeError on non-zero exit.
    """
    cmd = [
        _scannerctl, subcmd, _image_url(image_ref),
        "--indexer-address", _indexer_addr,
        "--matcher-address", _matcher_addr,
        "--insecure-skip-tls-verify",
    ]
    if extra:
        cmd += extra
    env = {**os.environ}
    auth = _auth_for_image(image_ref)
    if auth:
        env["ROX_SCANNERCTL_BASIC_AUTH"] = auth
    else:
        env.pop("ROX_SCANNERCTL_BASIC_AUTH", None)  # force anonymous for public registries
    proc = subprocess.run(cmd, capture_output=True, env=env)
    if proc.returncode != 0:
        snippet = (proc.stderr or b"").decode().strip()[:500]
        raise RuntimeError(f"scannerctl {subcmd} exited {proc.returncode}: {snippet}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        snippet = (proc.stdout or b"").decode().strip()[:300]
        raise RuntimeError(f"scannerctl {subcmd}: invalid JSON ({exc}): {snippet}")


def _scan_image(image_ref: str) -> dict:
    """Index + scan an image → Scanner V4 VulnerabilityReport (dict)."""
    return _run_scannerctl("scan", image_ref)


def _index_image(image_ref: str) -> dict:
    """Index only → IndexReport (dict), used as a fallback for contents."""
    return _run_scannerctl("scan", image_ref, extra=["--index-only"])


def _sbom_image(image_ref: str) -> dict:
    """Generate SPDX 2.3 SBOM (dict) for an image."""
    return _run_scannerctl("sbom", image_ref)


# ── Data conversion ─────────────────────────────────────────────────────────--

def _contents_pkg_index(contents: dict) -> dict:
    """Map package id → package dict from a Contents block."""
    return {p.get("id"): p for p in (contents.get("packages") or []) if p.get("id")}


def _src_map_from_contents(contents: dict) -> dict:
    """binary package name → source package name, from Contents.packages[].source.

    Used by the VEX engine to resolve RHEL findings reported against a binary
    RPM back to the source package the VEX statement is keyed on.
    """
    src_map: dict = {}
    for pkg in contents.get("packages") or []:
        name = pkg.get("name", "")
        src = (pkg.get("source") or {}).get("name", "")
        if name and src and src != name:
            src_map[name] = src
    return src_map


def clair_to_df(report: dict) -> pd.DataFrame:
    """Flatten a Scanner V4 VulnerabilityReport into the standard triage schema.

    Rows are built by iterating ``package_vulnerabilities`` (package_id → vuln ids)
    and resolving each package_id against ``contents.packages`` — the map key is the
    authoritative package id. Only CVE-prefixed findings are kept (Red Hat VEX is
    keyed by CVE). Duplicate (CVE, component, version) rows are dropped.
    """
    _COLS = ["COMPONENT", "VERSION", "CVE", "SEVERITY", "CVSS",
             "LINK", "FIXED_VERSION", "ADVISORY", "ADVISORY_LINK"]
    vulns = report.get("vulnerabilities") or {}
    pkg_vulns = report.get("package_vulnerabilities") or {}
    pkg_by_id = _contents_pkg_index(report.get("contents") or {})

    rows = []
    seen: set = set()

    def _emit(pkg_id: str, vuln_ids: list):
        pkg = pkg_by_id.get(pkg_id, {})
        comp = pkg.get("name", "")
        ver = pkg.get("version", "")
        for vid in vuln_ids:
            vuln = vulns.get(vid)
            if not vuln:
                continue
            cve = (vuln.get("name") or "").upper().strip()
            if not cve.startswith("CVE-"):
                continue
            # Fall back to the vuln's own package_id if the package wasn't in contents.
            c_comp, c_ver = comp, ver
            if not c_comp and vuln.get("package_id"):
                p2 = pkg_by_id.get(vuln["package_id"], {})
                c_comp, c_ver = p2.get("name", ""), p2.get("version", "")
            key = (cve, c_comp, c_ver)
            if key in seen:
                continue
            seen.add(key)
            adv = vuln.get("advisory") or {}
            rows.append({
                "COMPONENT":     c_comp,
                "VERSION":       c_ver,
                "CVE":           cve,
                "SEVERITY":      _normalized_severity(vuln),
                "CVSS":          _best_cvss(vuln),
                "LINK":          f"https://access.redhat.com/security/cve/{cve.lower()}",
                "FIXED_VERSION": vuln.get("fixed_in_version") or "",
                "ADVISORY":      adv.get("name") or "",
                "ADVISORY_LINK": adv.get("link") or "",
            })

    if pkg_vulns:
        for pkg_id, vlist in pkg_vulns.items():
            ids = vlist.get("values", []) if isinstance(vlist, dict) else (vlist or [])
            _emit(pkg_id, ids)
    else:
        # No package map (shouldn't happen) — group by each vuln's own package_id.
        by_pkg: dict = {}
        for vid, vuln in vulns.items():
            by_pkg.setdefault(vuln.get("package_id", ""), []).append(vid)
        for pkg_id, ids in by_pkg.items():
            _emit(pkg_id, ids)

    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=_COLS)


def _os_info_from_contents(contents: dict) -> str:
    """Human-readable OS string from the first distribution in Contents."""
    for dist in contents.get("distributions") or []:
        pretty = dist.get("pretty_name", "")
        if pretty:
            return pretty
        name = dist.get("name", "")
        ver = dist.get("version", "") or dist.get("version_id", "")
        if name or ver:
            return f"{name} {ver}".strip()
    return ""


def _best_redhat_cpe(contents: dict) -> str:
    """Pick the most authoritative Red Hat CPE from distributions, then repositories.

    Scanner V4 reports carry no OCI image labels, but distributions and
    repositories expose content-set CPEs (e.g. cpe:/o:redhat:enterprise_linux:9::baseos),
    which is what parse_context_from_labels uses to refine the RHEL version and
    VEX product scope.
    """
    for dist in contents.get("distributions") or []:
        cpe = dist.get("cpe", "")
        if cpe and "redhat" in cpe:
            return cpe
    for repo in contents.get("repositories") or []:
        cpe = repo.get("cpe", "")
        if cpe and "redhat" in cpe:
            return cpe
    # last resort: any cpe at all
    for dist in contents.get("distributions") or []:
        if dist.get("cpe"):
            return dist["cpe"]
    return ""


def _ctx_from_clair(report: dict, image_ref: str,
                    ocp_ver: Optional[str] = None,
                    comp_name: Optional[str] = None) -> WorkloadContext:
    """Derive a WorkloadContext from the Scanner V4 report + image reference.

    Scanner V4 emits no OCI labels, so namespace/type/VEX-prefix resolution comes
    from parse_image_ref (image-ref string parsing). We refine the RHEL version and
    CPE-based scope by synthesising a `cpe` label from the report's distribution /
    repository content-set CPEs and feeding it through parse_context_from_labels —
    the same authoritative code path the RHACS scanner uses.
    """
    contents = report.get("contents") or {}
    cpe = _best_redhat_cpe(contents)
    if cpe:
        ctx = parse_context_from_labels({"cpe": cpe}, image_ref)
    else:
        ctx = parse_image_ref(image_ref)

    # Fallback RHEL-version refinement straight from the distribution block.
    if not ctx.rhel_ver:
        for dist in contents.get("distributions") or []:
            did = (dist.get("did") or dist.get("name") or "").lower()
            if any(k in did for k in ("rhel", "redhat", "red hat", "centos")):
                m = re.match(r"^(\d+)", dist.get("version_id") or dist.get("version") or "")
                if m:
                    ctx.rhel_ver = m.group(1)
                    break

    ctx.sbom_src_map = _src_map_from_contents(contents)

    if ocp_ver:
        minor_ver = ".".join(ocp_ver.split(".")[:2])
        ctx.workload_type = "ocp"
        ctx.ocp_ver = minor_ver
        ctx.display_name = f"OpenShift {ocp_ver}"
        ctx.extra_prefixes = []
        if comp_name:
            cn_rhel = re.search(r"(?:rhel-[^-]+-|rhel-)(\d+)$", comp_name)
            if cn_rhel:
                ctx.rhel_ver = cn_rhel.group(1)

    return ctx


# ── SBOM cross-check (SPDX, no RHACS session) ─────────────────────────────────

def _verify_sbom_dict(sbom: dict, result_df: pd.DataFrame) -> dict:
    """Cross-check every unique (component, version) in result_df against an SPDX SBOM.

    Returns: {matched, total, mismatched, error}.
    """
    try:
        from lib4sbom.parser import SBOMParser as _SBOMParser
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        pkg_versions: dict = {}
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


# ── Per-image scan + audit pipeline ──────────────────────────────────────────

def _scan_and_audit(image_ref: str,
                    false_only: bool = False,
                    ocp_ver: Optional[str] = None,
                    comp_name: Optional[str] = None) -> dict:
    """Scan *image_ref* with Scanner V4, derive context, run the VEX audit."""
    try:
        report = _scan_image(image_ref)
    except Exception as exc:
        return {"found": None, "error": str(exc)}

    # If the vuln report didn't carry contents, fetch the index report for it.
    if not (report.get("contents") or {}).get("packages"):
        try:
            idx = _index_image(image_ref)
            report["contents"] = idx.get("contents", report.get("contents"))
        except Exception:
            pass

    ctx = _ctx_from_clair(report, image_ref, ocp_ver, comp_name)
    os_info = _os_info_from_contents(report.get("contents") or {})
    img_df = clair_to_df(report)

    if img_df.empty:
        return {"found": True, "img_ctx": ctx, "os_info": os_info,
                "result_df": None, "error": None}

    result_df = _audit_silent(img_df, ctx, false_only)
    return {"found": True, "img_ctx": ctx, "os_info": os_info,
            "result_df": result_df, "error": None}


# ── Display helper ────────────────────────────────────────────────────────────

def _display_result(console: Console, label: str, res: dict) -> None:
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
    global _basic_auth, _pull_secret_auths, _scannerctl, _indexer_addr, _matcher_addr

    parser = argparse.ArgumentParser(
        description=(
            "VEX triage using the local StackRox Scanner V4 (ClairCore) — no RHACS.\n"
            "Reuses the triage.py VEX engine; only the scanner source is swapped."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--image", default=None, metavar="IMAGE_REF",
                        help="Container image to scan and triage.")
    parser.add_argument("--ocp", default=None, metavar="PULLSPECS_FILE",
                        help="Path to 'oc adm release info --pullspecs' output; "
                             "triages every unique component image.")
    parser.add_argument("--sbom", action="store_true", default=False,
                        help="Show the SPDX SBOM package list for --image.")
    parser.add_argument("--output", default=None, metavar="FILE",
                        help="Output file path for the triage report.")
    parser.add_argument("--format", default="csv", choices=["table", "csv", "json"],
                        dest="output_fmt",
                        help="Output format: csv (default), json, or table.")
    parser.add_argument("--false-only", action="store_true", default=False,
                        help="Only show FALSE POSITIVE findings.")
    parser.add_argument("--workers", type=int, default=4, metavar="N",
                        help="Parallel image workers for --ocp mode (default: 4).")
    parser.add_argument("--auth", default=None, metavar="USER:PASS",
                        help="Single registry basic-auth credential, applied to ALL "
                             "images. Overrides --pull-secret.")
    parser.add_argument("--pull-secret", default=None, metavar="FILE", dest="pull_secret",
                        help="Pull-secret file (raw Docker config or Kubernetes Secret "
                             "JSON). Per-image creds are matched by registry host — "
                             "use this for registry.redhat.io and multi-registry "
                             "OCP releases.")
    parser.add_argument("--indexer-address", default=DEFAULT_INDEXER, dest="indexer",
                        help=f"Scanner V4 indexer gRPC address (default: {DEFAULT_INDEXER}).")
    parser.add_argument("--matcher-address", default=DEFAULT_MATCHER, dest="matcher",
                        help=f"Scanner V4 matcher gRPC address (default: {DEFAULT_MATCHER}).")
    parser.add_argument("--scannerctl", default=None, dest="scannerctl_path",
                        help="Path to the scannerctl binary (overrides auto-detection).")
    args = parser.parse_args()

    if args.ocp and args.image:
        parser.error("--ocp and --image are mutually exclusive")
    if not args.image and not args.ocp:
        parser.error("Specify --image or --ocp")

    console = Console()

    try:
        configure(
            scannerctl=args.scannerctl_path,
            indexer=args.indexer,
            matcher=args.matcher,
            basic_auth=args.auth,
            pull_secret=args.pull_secret,
        )
    except Exception as exc:
        console.print(f"[bold red]❌ {exc}[/bold red]")
        raise SystemExit(1)

    if _pull_secret_auths:
        regs = ", ".join(sorted(_pull_secret_auths)) or "(none)"
        console.print(f"[dim]🔑 pull secret: {len(_pull_secret_auths)} registry cred(s) — {regs}[/dim]")
    console.print(f"[dim]scannerctl: {_scannerctl}  "
                  f"indexer={_indexer_addr} matcher={_matcher_addr}[/dim]")

    # ── SBOM mode ─────────────────────────────────────────────────────────────
    if args.sbom and args.image:
        console.print(f"\n[bold]Mode:[/bold] [cyan]SBOM (Scanner V4)[/cyan]  "
                      f"image=[cyan]{args.image}[/cyan]")
        try:
            console.print(f"📦 Generating SPDX SBOM for [cyan]{args.image}[/cyan]...")
            sbom = _with_spinner(console, "Indexing + generating SBOM", _sbom_image, args.image)
            pkgs_df = sbom_to_packages_df(sbom)
            created = (sbom.get("creationInfo") or {}).get("created", "")
            creators = ", ".join((sbom.get("creationInfo") or {}).get("creators", []))
            console.print(f"  SPDX version : [dim]{sbom.get('spdxVersion', '')}[/dim]")
            if created:
                console.print(f"  Created      : [dim]{created}[/dim]")
            if creators:
                console.print(f"  Tools        : [dim]{creators}[/dim]")
            console.print(f"  Packages     : [bold]{len(pkgs_df)}[/bold]")
            console.print()

            tbl = Table(title=f"SBOM Packages — [bold cyan]{args.image}[/bold cyan]",
                        box=box.ROUNDED, show_header=True, header_style="bold white")
            tbl.add_column("Package", style="cyan", no_wrap=True)
            tbl.add_column("Version", style="dim", max_width=40)
            tbl.add_column("Purpose", style="magenta", no_wrap=True)
            tbl.add_column("File", style="dim", max_width=45)
            for _, row in pkgs_df.iterrows():
                tbl.add_row(row["NAME"], row["VERSION"], row["PURPOSE"], row["FILE"])
            console.print(tbl)
            console.print()
        except Exception as exc:
            console.print(f"[bold red]❌ SBOM error: {exc}[/bold red]")
            raise SystemExit(1)
        if args.output_fmt == "table" and not args.output:
            raise SystemExit(0)

    # ── OCP release mode ────────────────────────────────────────────────────--
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
            console.print("  Create it with: oc adm release info <version> --pullspecs")
            raise SystemExit(1)

        console.print(
            f"\n[bold]Mode:[/bold] [cyan]OCP release (Scanner V4)[/cyan]  "
            f"file=[cyan]{args.ocp}[/cyan]  version=[cyan]{_ocp_ver or '?'}[/cyan]"
        )
        console.print(f"✅ Parsed [bold]{len(images)}[/bold] unique component image(s)")
        console.print(f"🚀 Scanning with [bold]{args.workers}[/bold] parallel worker(s)...\n")

        total = len(images)
        results_map: dict = {}
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            future_to_comp = {
                ex.submit(_scan_and_audit, image_ref, args.false_only, _ocp_ver, comp_name):
                    (comp_name, image_ref)
                for comp_name, image_ref in images
            }
            done = 0
            for future in as_completed(future_to_comp):
                done += 1
                comp_name, image_ref = future_to_comp[future]
                res = future.result()
                results_map[comp_name] = (image_ref, res)
                status = ("✅" if res.get("found") and res.get("result_df") is not None
                          else ("⚠ " if res.get("found") is False else "❌"))
                console.print(f"  [{done}/{total}] {status} {comp_name}", highlight=False)
        console.print()

        all_results: list = []
        for comp_name, image_ref in images:
            image_ref_stored, res = results_map.get(comp_name, (image_ref, {"found": False}))
            _display_result(console, f"{comp_name}  [dim]{image_ref_stored}[/dim]", res)
            if res.get("found") and res.get("result_df") is not None:
                r = res["result_df"].copy()
                r["OCP_COMPONENT"] = comp_name
                r["IMAGE"] = image_ref_stored
                all_results.append(r)

        console.rule("[bold]OCP Release Summary[/bold]")
        scanned = sum(1 for _, r in results_map.values() if r.get("found"))
        errors = [c for c, (_, r) in results_map.items() if r.get("error")]
        console.print(f"  Scanned : [bold]{scanned}[/bold] / {total} component image(s)")
        if errors:
            console.print(f"  Errors  : [red]{len(errors)}[/red] image(s) failed to scan")
        console.print()

        if all_results:
            combined = pd.concat(all_results, ignore_index=True)
            counts = combined["AUDIT_RESULT"].value_counts()
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
    console.print(f"[bold]Mode:[/bold]  [cyan]Scanner V4 scan[/cyan]")
    console.print("[dim]First scan pulls + indexes all layers inside the scanner "
                  "(network-bound); re-scans of the same digest are cached and fast.[/dim]")

    try:
        report = _with_spinner(console, "Scanning with local Scanner V4", _scan_image, args.image)
    except Exception as exc:
        console.print(f"[bold red]❌ Scanner V4 error: {exc}[/bold red]")
        raise SystemExit(1)

    if not (report.get("contents") or {}).get("packages"):
        try:
            idx = _with_spinner(console, "Fetching index report", _index_image, args.image)
            report["contents"] = idx.get("contents", report.get("contents"))
        except Exception:
            pass

    ctx = _ctx_from_clair(report, args.image)
    os_info = _os_info_from_contents(report.get("contents") or {})
    df = clair_to_df(report)

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

    # ── SBOM cross-check ──────────────────────────────────────────────────────
    if result_df is not None and not result_df.empty:
        try:
            sbom = _with_spinner(console, "Generating SBOM for cross-check", _sbom_image, args.image)
            sbom_s = _verify_sbom_dict(sbom, result_df)
            _print_sbom_summary(console, sbom_s)
        except Exception as exc:
            console.print(f"[dim]SBOM cross-check skipped: {exc}[/dim]")


if __name__ == "__main__":
    main()
