#!/usr/bin/env python3
"""
pipeline.py — Download OCP + operator catalogs and run the full VEX triage.

The one-command end-to-end pipeline (console script ``rhacs-vex-pipeline``).
Stages (all enabled by default; each has a --skip-* flag):
  0. podman login to the Red Hat registries.
  1. Render OLM operator index catalogs via opm (one per unique minor version).
  2. Build the namespace→VEX prefix map      (python -m rhacs_vex.ns_map).
  3. Fetch OCP release pullspecs via `oc adm release info` for each full version.
  4. Triage each OCP release                 (python -m rhacs_vex.triage --ocp).
  5. Triage all operators                     (python -m rhacs_vex.operators).

Requires:
  ROX_ENDPOINT   — RHACS Central hostname:port
  ROX_API_TOKEN  — RHACS API bearer token

Usage examples:
  # Full run with embedded version list
  rhacs-vex-pipeline --pull-secret ~/pullsecret.txt

  # Only download catalogs, skip scanning
  rhacs-vex-pipeline --pull-secret ~/pullsecret.txt --skip-ocp --skip-operators

  # Resume after an interruption, skip already-done items
  rhacs-vex-pipeline --pull-secret ~/pullsecret.txt --skip-existing

  # Supply a custom versions CSV
  rhacs-vex-pipeline --pull-secret ~/pullsecret.txt --versions my_versions.csv

Run from the repository root — all tool paths are relative to ./data.
"""

import argparse
import csv
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Embedded default version list (override with --versions)
# ---------------------------------------------------------------------------
EMBEDDED_VERSIONS_CSV = """\
Version,Release Status,Phase
4.22.1,Stable,Full Support
4.22.0,Generally Available,Full Support
4.21.20,Stable,Full Support
4.21.19,Stable,Full Support
4.21.18,Stable,Full Support
4.21.17,Stable,Full Support
4.21.16,Stable,Full Support
4.21.15,Stable,Full Support
4.21.14,Stable,Full Support
4.21.13,Stable,Full Support
4.21.12,Stable,Full Support
4.21.11,Stable,Full Support
4.21.10,Stable,Full Support
4.21.9,Stable,Full Support
4.21.8,Stable,Full Support
4.21.7,Stable,Full Support
4.21.6,Stable,Full Support
4.21.5,Stable,Full Support
4.21.4,Stable,Full Support
4.21.3,Stable,Full Support
4.21.2,Stable,Full Support
4.21.1,Stable,Full Support
4.21.0,Generally Available,Full Support
4.20.25,Stable,Full Support (EUS)
4.20.24,Stable,Full Support (EUS)
4.20.23,Stable,Full Support (EUS)
4.20.22,Stable,Full Support (EUS)
4.20.21,Stable,Full Support (EUS)
4.20.20,Stable,Full Support (EUS)
4.20.19,Stable,Full Support (EUS)
4.20.18,Stable,Full Support (EUS)
4.20.17,Stable,Full Support (EUS)
4.20.16,Stable,Full Support (EUS)
4.20.15,Stable,Full Support (EUS)
4.20.14,Stable,Full Support (EUS)
4.20.13,Stable,Full Support (EUS)
4.20.12,Stable,Full Support (EUS)
4.20.11,Stable,Full Support (EUS)
4.20.10,Stable,Full Support (EUS)
4.20.9,Stable,Full Support (EUS)
4.20.8,Stable,Full Support (EUS)
4.20.6,Stable,Full Support (EUS)
4.20.5,Stable,Full Support (EUS)
4.20.4,Stable,Full Support (EUS)
4.20.3,Stable,Full Support (EUS)
4.20.2,Stable,Full Support (EUS)
4.20.1,Stable,Full Support (EUS)
4.20.0,Generally Available,Full Support (EUS)
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CATALOG_DIR  = os.path.join("data", "catalogs")
REPORTS_DIR  = os.path.join("data", "reports")
PULLSPEC_DIR = os.path.join("data", "pullspecs")

# Triage modules run as subprocesses (`python -m ...`) for process isolation and
# stdout redirection.  RHACS Central API backend (needs ROX_ENDPOINT /
# ROX_API_TOKEN); OCP-release triage and operator triage respectively.
OCP_TRIAGE_MODULE      = "rhacs_vex.triage"
OPERATOR_TRIAGE_MODULE = "rhacs_vex.operators"


def log(msg: str):
    print(f"[rhacs-vex-pipeline] {msg}", flush=True)


def run(cmd: list[str], *, env: dict | None = None, capture_stdout: bool = False,
        output_file: str | None = None) -> int:
    """Run a subprocess.  Optionally redirect stdout to *output_file*."""
    display = " ".join(cmd)
    log(f"$ {display}" + (f"  > {output_file}" if output_file else ""))

    merged_env = {**os.environ, **(env or {})}

    if output_file:
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w") as fh:
            proc = subprocess.run(cmd, env=merged_env, stdout=fh, stderr=None)
    elif capture_stdout:
        proc = subprocess.run(cmd, env=merged_env, capture_output=True, text=True)
    else:
        proc = subprocess.run(cmd, env=merged_env)

    if proc.returncode != 0:
        log(f"ERROR: command exited with code {proc.returncode}")

    return proc.returncode


def load_versions(csv_path: str | None) -> list[str]:
    """Return a list of full version strings, e.g. ['4.21.1', '4.20.5', ...]."""
    if csv_path:
        with open(csv_path) as fh:
            text = fh.read()
    else:
        text = EMBEDDED_VERSIONS_CSV

    reader = csv.DictReader(io.StringIO(text))
    versions = []
    for row in reader:
        ver = row.get("Version", "").strip()
        if ver:
            versions.append(ver)
    return versions


def minor(version: str) -> str:
    """'4.21.3' → '4.21'"""
    parts = version.split(".")
    return ".".join(parts[:2])


# ---------------------------------------------------------------------------
# Stage 0 — podman login
# ---------------------------------------------------------------------------

REGISTRIES_TO_LOGIN = [
    "registry.redhat.io",
    "quay.io",
    "registry.connect.redhat.com",
]

def _is_logged_in(podman_bin: str, registry: str, pull_secret: str) -> bool:
    """Return True if podman can already authenticate to *registry*."""
    proc = subprocess.run(
        [podman_bin, "login", "--authfile", os.path.abspath(pull_secret),
         "--get-login", registry],
        capture_output=True, text=True,
    )
    return proc.returncode == 0 and proc.stdout.strip() != ""


def stage_podman_login(pull_secret: str, podman_bin: str):
    """Log in to Red Hat registries, skipping any that already have valid credentials."""
    log("=== STAGE 0: podman login to Red Hat registries ===")
    failed = []
    for registry in REGISTRIES_TO_LOGIN:
        if _is_logged_in(podman_bin, registry, pull_secret):
            log(f"  SKIP  {registry} (already logged in)")
            continue
        rc = run([podman_bin, "login", "--authfile", os.path.abspath(pull_secret), registry])
        if rc != 0:
            log(f"  WARNING: podman login failed for {registry}")
            failed.append(registry)
        else:
            log(f"  OK    {registry}")
    if failed:
        log(f"  WARNING: could not log in to: {', '.join(failed)} — subsequent stages may fail")


# ---------------------------------------------------------------------------
# Stage 1 — operator index catalogs
# ---------------------------------------------------------------------------

def _age_days(path: str) -> float:
    import time
    return (time.time() - os.path.getmtime(path)) / 86400.0


def stage_catalogs(minor_versions: list[str], pull_secret: str,
                   opm_bin: str, skip_existing: bool, max_age_days: int = 7):
    log("=== STAGE 1: Render operator index catalogs ===")
    os.makedirs(CATALOG_DIR, exist_ok=True)

    abs_pull_secret = os.path.abspath(pull_secret)

    # Some versions of opm / containers-image don't honour REGISTRY_AUTH_FILE.
    # Also export DOCKER_CONFIG pointing to a temp dir with the pull-secret
    # copied as config.json so every fallback path finds valid credentials.
    tmpdir = tempfile.mkdtemp(prefix="opm_auth_")
    try:
        shutil.copy2(abs_pull_secret, os.path.join(tmpdir, "config.json"))
        env = {
            "REGISTRY_AUTH_FILE": abs_pull_secret,
            "DOCKER_CONFIG": tmpdir,
        }

        for mv in minor_versions:
            dest = os.path.join(CATALOG_DIR, f"catalog-{mv}.json")
            if os.path.exists(dest) and os.path.getsize(dest) > 0:
                age = _age_days(dest)
                if max_age_days <= 0 or age < max_age_days:
                    log(f"  SKIP  catalog-{mv}.json ({os.path.getsize(dest) / 1e6:.0f} MB, {age:.1f}d old)")
                    continue
                log(f"  STALE catalog-{mv}.json ({age:.1f}d > {max_age_days}d) — re-rendering")

            # Render to a temp file first so a failed render never clobbers
            # the previous good catalog.
            image = f"registry.redhat.io/redhat/redhat-operator-index:v{mv}"
            tmp_dest = dest + ".tmp"
            rc = run([opm_bin, "render", image, "-o", "json"], env=env,
                     output_file=tmp_dest)
            if rc == 0 and os.path.exists(tmp_dest) and os.path.getsize(tmp_dest) > 0:
                os.replace(tmp_dest, dest)
            else:
                log(f"  WARNING: opm render failed for {mv} — keeping previous catalog")
                if os.path.exists(tmp_dest):
                    os.remove(tmp_dest)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Stage 2 — namespace→VEX prefix map
# ---------------------------------------------------------------------------

def stage_ns_map():
    log("=== STAGE 2: Build namespace VEX prefix map ===")
    rc = run([sys.executable, "-m", "rhacs_vex.ns_map"])
    if rc != 0:
        log("WARNING: rhacs_vex.ns_map exited non-zero")


# ---------------------------------------------------------------------------
# Stage 3 — OCP release pullspecs
# ---------------------------------------------------------------------------

def stage_ocp_pullspecs(versions: list[str], pull_secret: str, oc_bin: str,
                         arch: str, skip_existing: bool) -> list[str]:
    """
    Fetch release pullspecs for each version and return a list of txt paths
    that were successfully created.
    """
    log("=== STAGE 3: Fetch OCP release pullspecs ===")
    os.makedirs(PULLSPEC_DIR, exist_ok=True)
    ready = []

    for ver in versions:
        dest = os.path.join(PULLSPEC_DIR, f"{ver}.txt")
        if os.path.exists(dest) and os.path.getsize(dest) > 0:
            log(f"  SKIP  {dest} (already exists)")
            ready.append(dest)
            continue

        release_ref = f"quay.io/openshift-release-dev/ocp-release:{ver}-{arch}"
        rc = run(
            [oc_bin, "adm", "release", "info", release_ref,
             "--pullspecs", f"--registry-config={os.path.abspath(pull_secret)}"],
            output_file=dest,
        )
        if rc == 0:
            ready.append(dest)
        else:
            log(f"  WARNING: could not fetch pullspecs for {ver}")
            # Remove empty/partial file so it doesn't trip up triage.py
            if os.path.exists(dest):
                os.remove(dest)

    return ready


# ---------------------------------------------------------------------------
# Stage 4 — OCP release triage
# ---------------------------------------------------------------------------

def stage_ocp_triage(pullspec_files: list[str], workers: int,
                     skip_existing: bool, false_only: bool,
                     max_report_age: int = 7):
    log("=== STAGE 4: Triage OCP releases (rhacs) ===")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    for txt in pullspec_files:
        # Derive version from filename  e.g. "4.21.3.txt" → "4.21.3"
        ver = os.path.splitext(os.path.basename(txt))[0]
        out = os.path.join(REPORTS_DIR, f"ocp-{ver}.csv")

        if os.path.exists(out) and os.path.getsize(out) > 0:
            # Two independent freshness dimensions:
            #  - completeness: every manifest component scanned
            #  - verdict age:  VEX data updates daily; reports older than
            #    --max-report-age get re-audited.  Re-runs are cheap and
            #    Central-friendly: digest-pinned scans/SBOMs come from the
            #    permanent local cache, only VEX re-syncs (ETag/304).
            try:
                import pandas as pd, re as _re
                _df = pd.read_csv(out)
                _scanned = _df['OCP_COMPONENT'].nunique() if 'OCP_COMPONENT' in _df.columns else 0
                _expected = sum(1 for line in open(txt)
                                if _re.match(r'^\S+\s+\S+@sha256:[a-f0-9]+', line.strip()))
                _age = _age_days(out)
                if _scanned < _expected:
                    log(f"  RERUN {out} (incomplete: {_scanned}/{_expected} components)")
                    os.remove(out)
                elif max_report_age > 0 and _age >= max_report_age:
                    log(f"  STALE {out} ({_age:.1f}d > {max_report_age}d) — re-auditing from cached scans")
                else:
                    log(f"  SKIP  {out} ({_scanned}/{_expected} components, {_age:.1f}d old)")
                    continue
            except Exception:
                log(f"  SKIP  {out} (already exists)")
                continue

        cmd = [
            sys.executable, "-m", OCP_TRIAGE_MODULE,
            "--ocp", txt,
            "--format", "csv",
            "--output", out,
            "--workers", str(workers),
        ]
        if false_only:
            cmd.append("--false-only")

        rc = run(cmd)
        if rc != 0:
            log(f"  WARNING: {OCP_TRIAGE_MODULE} exited non-zero for {ver} (rc={rc})")


# ---------------------------------------------------------------------------
# Stage 5a — operator report prefill: REMOVED
# ---------------------------------------------------------------------------
# Operator reports are now stored flat (data/reports/operators/, one CSV per
# unique bundle) with the minor→bundle association in operators_index.json, so
# the old cross-version prefill/copy is obsolete — deduplication is structural.


# ---------------------------------------------------------------------------
# Stage 5 — operator triage
# ---------------------------------------------------------------------------

def stage_operator_triage(minor_versions: list[str], workers: int,
                           skip_existing: bool, false_only: bool):
    log("=== STAGE 5: Triage operators (rhacs) ===")

    cmd = [
        sys.executable, "-m", OPERATOR_TRIAGE_MODULE,
        "--version", ",".join(minor_versions),
        "--workers", str(workers),
    ]
    if skip_existing:
        cmd.append("--skip-existing")
    if false_only:
        cmd.append("--false-only")

    rc = run(cmd)
    if rc != 0:
        log(f"WARNING: {OPERATOR_TRIAGE_MODULE} exited non-zero")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download OCP + operator catalogs and run full VEX triage.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--pull-secret", required=True, metavar="FILE",
        help="Path to your Red Hat pull-secret JSON file (used by opm and oc).",
    )
    parser.add_argument(
        "--versions", default=None, metavar="CSV_FILE",
        help="Path to a CSV file with a 'Version' column listing OCP versions to process. "
             "Defaults to the versions embedded in this script.",
    )
    parser.add_argument(
        "--arch", default="x86_64", metavar="ARCH",
        help="CPU architecture used when resolving OCP release images (default: x86_64).",
    )
    parser.add_argument(
        "--podman", default="podman", metavar="PATH",
        help="Path to the podman binary (default: podman, assumed on PATH).",
    )
    parser.add_argument(
        "--opm", default="opm", metavar="PATH",
        help="Path to the opm binary (default: opm, assumed on PATH).",
    )
    parser.add_argument(
        "--oc", default="oc", metavar="PATH",
        help="Path to the oc binary (default: oc, assumed on PATH).",
    )
    parser.add_argument(
        "--workers", type=int, default=10, metavar="N",
        help="Parallel image workers passed to the triage / operators stages (default: 10).",
    )
    parser.add_argument(
        "--false-only", action="store_true", default=False,
        help="Only include FALSE POSITIVE findings in output CSVs.",
    )
    parser.add_argument(
        "--skip-existing", action="store_true", default=False,
        help="Skip catalogs / pullspec files / reports that already exist on disk. "
             "Useful for resuming an interrupted run.",
    )
    parser.add_argument(
        "--max-report-age", type=int, default=7, metavar="DAYS",
        help="Re-audit OCP report CSVs older than this many days so verdicts track "
             "current VEX data (0 = never). Re-runs use the permanent digest-pinned "
             "scan/SBOM cache — no extra load on RHACS Central. Default: 7.",
    )
    parser.add_argument(
        "--max-catalog-age", type=int, default=7, metavar="DAYS",
        help="Re-render operator index catalogs older than this many days so new "
             "bundle versions get picked up (0 = never). Default: 7.",
    )
    parser.add_argument(
        "--refresh-operator-verdicts", action="store_true", default=False,
        help="After Stage 5, re-audit all operator report verdicts offline from "
             "cached scans (python -m rhacs_vex.retriage) — CPU only, zero Central load.",
    )

    # Stage skip flags
    skip = parser.add_argument_group("skip stages")
    skip.add_argument("--skip-login",     action="store_true", default=False,
                      help="Skip Stage 0: do not run podman login before pulling images.")
    skip.add_argument("--skip-catalogs",  action="store_true", default=False,
                      help="Skip Stage 1: do not (re-)download operator index catalogs.")
    skip.add_argument("--skip-ns-map",    action="store_true", default=False,
                      help="Skip Stage 2: do not rebuild the namespace→VEX prefix map.")
    skip.add_argument("--skip-ocp",       action="store_true", default=False,
                      help="Skip Stages 3+4: do not fetch pullspecs or triage OCP releases.")
    skip.add_argument("--skip-operators", action="store_true", default=False,
                      help="Skip Stage 5: do not triage operators.")

    return parser.parse_args()


def main():
    args = parse_args()

    # ── Validate pull-secret ────────────────────────────────────────────────
    pull_secret = os.path.expanduser(args.pull_secret)
    if not os.path.isfile(pull_secret):
        sys.exit(f"ERROR: pull-secret file not found: {pull_secret}")

    # ── Check required env vars for scanning stages ─────────────────────────
    if not args.skip_ocp or not args.skip_operators:
        missing = [v for v in ("ROX_ENDPOINT", "ROX_API_TOKEN")
                   if not os.environ.get(v)]
        if missing:
            sys.exit(
                f"ERROR: required environment variable(s) not set: {', '.join(missing)}\n"
                "  export ROX_ENDPOINT=central.example.com:443\n"
                "  export ROX_API_TOKEN=<your-token>\n"
                "  (or pass --skip-ocp --skip-operators to run the non-scanning stages)"
            )

    # ── Load version list ───────────────────────────────────────────────────
    versions = load_versions(args.versions)
    if not versions:
        sys.exit("ERROR: no versions found — check your --versions CSV file.")

    minor_versions_ordered = list(dict.fromkeys(minor(v) for v in versions))

    log(f"Full versions  : {len(versions)}")
    log(f"Minor versions : {minor_versions_ordered}")

    # ── Stage 0: podman login ───────────────────────────────────────────────
    if not args.skip_login:
        stage_podman_login(pull_secret, args.podman)
    else:
        log("=== STAGE 0: SKIPPED (--skip-login) ===")

    # ── Stage 1: operator catalogs ──────────────────────────────────────────
    if not args.skip_catalogs:
        stage_catalogs(minor_versions_ordered, pull_secret, args.opm,
                       args.skip_existing, max_age_days=args.max_catalog_age)
    else:
        log("=== STAGE 1: SKIPPED (--skip-catalogs) ===")

    # ── Stage 2: namespace map ──────────────────────────────────────────────
    if not args.skip_ns_map:
        stage_ns_map()
    else:
        log("=== STAGE 2: SKIPPED (--skip-ns-map) ===")

    # ── Stages 3+4: OCP release pullspecs + triage ──────────────────────────
    if not args.skip_ocp:
        pullspec_files = stage_ocp_pullspecs(
            versions, pull_secret, args.oc, args.arch, args.skip_existing
        )
        stage_ocp_triage(pullspec_files, args.workers, args.skip_existing,
                         args.false_only, max_report_age=args.max_report_age)
    else:
        log("=== STAGES 3+4: SKIPPED (--skip-ocp) ===")

    # ── Stage 5: operator triage ─────────────────────────────────────────────
    if not args.skip_operators:
        log("=== STAGE 5a: Prefill no longer needed (flat operator storage) ===")
        stage_operator_triage(
            minor_versions_ordered, args.workers, True, args.false_only
        )
    else:
        log("=== STAGE 5: SKIPPED (--skip-operators) ===")

    # ── Stage 6: offline verdict refresh for operators ──────────────────────
    # Operator report filenames encode the bundle version, so skip-existing is
    # correct for scan coverage — but the VEX verdicts inside age.  The offline
    # retriage recomputes them from cached scans with zero RHACS/network load.
    if args.refresh_operator_verdicts and not args.skip_operators:
        log("=== STAGE 6: Offline operator verdict refresh (no Central load) ===")
        run([sys.executable, "-m", "rhacs_vex.retriage",
             "--operators-only",
             "--version", ",".join(minor_versions_ordered),
             "--workers", str(args.workers)])
    elif not args.skip_operators:
        log("HINT: operator verdicts age as VEX updates — refresh offline anytime with:")
        log(f"      python3 -m rhacs_vex.retriage --operators-only --version {','.join(minor_versions_ordered)}")

    log("All stages complete.")


if __name__ == "__main__":
    main()
