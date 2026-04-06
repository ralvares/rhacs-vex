#!/usr/bin/env python3
"""
setup_and_scan.py — Download OCP + operator catalogs and run full VEX triage.

Pipeline stages (all enabled by default):
  1. Render OLM operator index catalogs via opm (one per unique minor version).
  2. Build the namespace→VEX prefix map  (build_ns_map.py).
  3. Fetch OCP release pullspecs via `oc adm release info` for each full version.
  4. Triage each OCP release          (triage.py --ocp ...).
  5. Triage all operators             (triage_operators.py).

Requires:
  ROX_ENDPOINT   — RHACS Central hostname:port
  ROX_API_TOKEN  — RHACS API bearer token

Usage examples:
  # Full run with embedded version list
  python3 setup_and_scan.py --pull-secret ~/pullsecret.txt

  # Only download catalogs, skip scanning
  python3 setup_and_scan.py --pull-secret ~/pullsecret.txt --skip-ocp --skip-operators

  # Resume after an interruption, skip already-done items
  python3 setup_and_scan.py --pull-secret ~/pullsecret.txt --skip-existing

  # Supply a custom versions CSV
  python3 setup_and_scan.py --pull-secret ~/pullsecret.txt --versions my_versions.csv
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
4.21.8,Stable,Full Support
4.21.7,Stable,Full Support
4.21.6,Stable,Full Support
4.21.5,Stable,Full Support
4.21.4,Stable,Full Support
4.21.3,Stable,Full Support
4.21.2,Stable,Full Support
4.21.1,Stable,Full Support
4.21.0,Generally Available,Full Support
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
4.20.7,Stable,Full Support (EUS)
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

CATALOG_DIR = os.path.join("data", "catalogs")
REPORTS_DIR = os.path.join("data", "reports")


def log(msg: str):
    print(f"[setup_and_scan] {msg}", flush=True)


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

def stage_podman_login(pull_secret: str, podman_bin: str):
    """Log in to Red Hat registries using the pull-secret as the auth file."""
    log("=== STAGE 0: podman login to Red Hat registries ===")
    failed = []
    for registry in REGISTRIES_TO_LOGIN:
        rc = run([podman_bin, "login", "--authfile", os.path.abspath(pull_secret), registry])
        if rc != 0:
            log(f"  WARNING: podman login failed for {registry}")
            failed.append(registry)
    if failed:
        log(f"  WARNING: could not log in to: {', '.join(failed)} — subsequent stages may fail")
    else:
        log("  All registry logins succeeded.")


# ---------------------------------------------------------------------------
# Stage 1 — operator index catalogs
# ---------------------------------------------------------------------------

def stage_catalogs(minor_versions: list[str], pull_secret: str,
                   opm_bin: str, skip_existing: bool):
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
            if skip_existing and os.path.exists(dest):
                log(f"  SKIP  catalog-{mv}.json (already exists)")
                continue

            image = f"registry.redhat.io/redhat/redhat-operator-index:v{mv}"
            rc = run([opm_bin, "render", image, "-o", "json"], env=env,
                     output_file=dest)
            if rc != 0:
                log(f"  WARNING: opm render failed for {mv} — removing empty output")
                # Remove the empty file so stage 2 doesn't process a blank catalog.
                if os.path.exists(dest) and os.path.getsize(dest) == 0:
                    os.remove(dest)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Stage 2 — namespace→VEX prefix map
# ---------------------------------------------------------------------------

def stage_ns_map():
    log("=== STAGE 2: Build namespace VEX prefix map ===")
    rc = run([sys.executable, "build_ns_map.py"])
    if rc != 0:
        log("WARNING: build_ns_map.py exited non-zero")


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
    ready = []

    for ver in versions:
        dest = f"{ver}.txt"
        if skip_existing and os.path.exists(dest):
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
                     skip_existing: bool, false_only: bool):
    log("=== STAGE 4: Triage OCP releases ===")
    os.makedirs(REPORTS_DIR, exist_ok=True)

    for txt in pullspec_files:
        # Derive version from filename  e.g. "4.21.3.txt" → "4.21.3"
        ver = os.path.splitext(os.path.basename(txt))[0]
        out = os.path.join(REPORTS_DIR, f"ocp-{ver}.csv")

        if skip_existing and os.path.exists(out):
            log(f"  SKIP  {out} (already exists)")
            continue

        cmd = [
            sys.executable, "triage.py",
            "--ocp", txt,
            "--format", "csv",
            "--output", out,
            "--workers", str(workers),
        ]
        if false_only:
            cmd.append("--false-only")

        rc = run(cmd)
        if rc != 0:
            log(f"  WARNING: triage.py exited non-zero for {ver}")


# ---------------------------------------------------------------------------
# Stage 5a — pre-fill duplicate operator reports across minor versions
# ---------------------------------------------------------------------------

def stage_prefill_operator_reports(minor_versions: list[str]) -> int:
    """
    Parse every local catalog and build a cross-version map of expected report
    basenames.  The filename {operator}-{channel}-{bundle_version}.csv is a
    content fingerprint: same name = same head bundle = same images = same
    scan result.

    If a file already exists under any ocp-{ver}/ directory, copy it to every
    other version directory that expects the same file.  The subsequent
    triage_operators --skip-existing call then skips all pre-populated entries,
    avoiding redundant RHACS scans.

    Returns the total number of files copied.
    """
    log("=== STAGE 5a: Pre-fill shared operator reports across minor versions ===")

    # Import catalog helpers (no credentials needed for parsing).
    import triage_operators as _to

    # basename → {ocp_minor_ver: absolute_dest_path}
    basename_map: dict[str, dict[str, str]] = {}

    for ver in minor_versions:
        cat_path = os.path.join(CATALOG_DIR, f"catalog-{ver}.json")
        if not os.path.exists(cat_path):
            log(f"  SKIP  catalog-{ver}.json not found — cannot prefill for {ver}")
            continue
        try:
            op_index = _to.build_operator_index(cat_path)
        except Exception as exc:
            log(f"  WARNING: failed to parse catalog-{ver}.json: {exc}")
            continue

        for op_name, ch_entries in op_index.items():
            for ch_entry in ch_entries:
                channel     = ch_entry["channel"]
                bundle      = ch_entry["head_bundle"]
                bundle_name = bundle.get("name", "")

                # Mirror the version extraction logic in triage_operators.py main().
                _vm = re.search(r"\.v(\d)", bundle_name)
                if _vm:
                    bundle_version = bundle_name[_vm.start(0) + 1:]
                elif bundle_name.startswith(op_name + "."):
                    bundle_version = bundle_name[len(op_name) + 1:]
                else:
                    bundle_version = bundle_name

                dest = _to._report_path(ver, op_name, channel, bundle_version)
                basename_map.setdefault(os.path.basename(dest), {})[ver] = dest

    copied = 0
    for basename, ver_paths in basename_map.items():
        if len(ver_paths) < 2:
            continue  # only appears in one version catalog — nothing to share

        existing = {v: p for v, p in ver_paths.items() if os.path.exists(p)}
        if not existing:
            continue  # not yet scanned anywhere

        src_ver, src_path = next(iter(existing.items()))
        for dest_ver, dest_path in ver_paths.items():
            if os.path.exists(dest_path):
                continue  # already present in this version dir
            log(f"  COPY  {basename}  ({src_ver} → {dest_ver})")
            shutil.copy2(src_path, dest_path)
            copied += 1

    log(f"  Pre-filled {copied} shared report(s) — triage will skip these.")
    return copied


# ---------------------------------------------------------------------------
# Stage 5 — operator triage
# ---------------------------------------------------------------------------

def stage_operator_triage(minor_versions: list[str], workers: int,
                           skip_existing: bool, false_only: bool):
    log("=== STAGE 5: Triage operators ===")

    cmd = [
        sys.executable, "triage_operators.py",
        "--version", ",".join(minor_versions),
        "--workers", str(workers),
    ]
    if skip_existing:
        cmd.append("--skip-existing")
    if false_only:
        cmd.append("--false-only")

    rc = run(cmd)
    if rc != 0:
        log("WARNING: triage_operators.py exited non-zero")


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
        help="Parallel image workers passed to triage.py and triage_operators.py (default: 10).",
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
                "  export ROX_API_TOKEN=<your-token>"
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
        stage_catalogs(minor_versions_ordered, pull_secret, args.opm, args.skip_existing)
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
        stage_ocp_triage(pullspec_files, args.workers, args.skip_existing, args.false_only)
    else:
        log("=== STAGES 3+4: SKIPPED (--skip-ocp) ===")

    # ── Stage 5: operator triage ─────────────────────────────────────────────
    if not args.skip_operators:
        stage_prefill_operator_reports(minor_versions_ordered)
        stage_operator_triage(
            minor_versions_ordered, args.workers, True, args.false_only
        )
    else:
        log("=== STAGE 5: SKIPPED (--skip-operators) ===")

    log("All stages complete.")


if __name__ == "__main__":
    main()
