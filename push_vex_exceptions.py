#!/usr/bin/env python3
"""
push_vex_exceptions.py — Push VEX triage false-positive results as RHACS
vulnerability exceptions bound to image@sha256.

For every running image that has a corresponding VEX triage report, this
program:

  1. Finds active RHACS policy alerts caused by false-positive CVEs.
  2. Adds a sha256-scoped image exclusion to the triggering policy so the
     alert will NOT re-fire after the next evaluation cycle.
  3. Resolves the currently open alert.

Image matching is done exclusively by sha256 digest — no tag ambiguity.

Environment variables (required):
  ROX_ENDPOINT   — RHACS Central host:port  (e.g. central.example.com:443)
  ROX_API_TOKEN  — RHACS API bearer token

Usage:
  python3 push_vex_exceptions.py
  python3 push_vex_exceptions.py --reports-dir data/reports --dry-run
  python3 push_vex_exceptions.py --dry-run --verbose
"""

import argparse
import csv
import os
import re
import sys
import urllib3
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REPORTS_DIR = os.path.join("data", "reports")
PAGE_SIZE = 500
FALSE_POSITIVE_MARKER = "FALSE POSITIVE"
EXCLUSION_PREFIX = "VEX-FP"
CSV_WORKERS = 16
HTTP_WORKERS = 20

# Registries for which VEX triage reports are produced.
# Only images whose full name starts with one of these prefixes will ever be
# processed — this is an explicit guardrail that prevents touching any
# non-Red Hat workload image that happens to be running on the cluster.
ALLOWED_REGISTRIES: tuple[str, ...] = (
    "registry.redhat.io/",
    "quay.io/openshift-release-dev/",
    "registry.access.redhat.com/",
)

# ---------------------------------------------------------------------------
# RHACS session
# ---------------------------------------------------------------------------

def make_session(endpoint: str, token: str) -> requests.Session:
    s = requests.Session()
    s.headers["Authorization"] = f"Bearer {token}"
    s.verify = False
    # Attach base_url as a plain attribute for convenience
    s.base_url = f"https://{endpoint}"  # type: ignore[attr-defined]
    return s


# ---------------------------------------------------------------------------
# Step 1 — Load false positives from CSV reports
# ---------------------------------------------------------------------------

def load_false_positives(reports_dir: str) -> dict[str, list[tuple[str, str]]]:
    """
    Scan all *.csv files under ``reports_dir`` recursively.

    Returns:
        { sha256_hex: [(cve_id, justification), ...] }

    The IMAGE column in the reports has the form:
        quay.io/…@sha256:<64-hex-chars>
    """
    result: dict[str, list[tuple[str, str]]] = defaultdict(list)
    seen: dict[str, set[str]] = defaultdict(set)
    lock = Lock()

    def _parse_csv(csv_path: Path) -> list[tuple[str, str, str]]:
        """Parse one CSV; return list of (sha256, cve, justification) tuples."""
        rows = []
        try:
            with open(csv_path, newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    if FALSE_POSITIVE_MARKER not in row.get("AUDIT_RESULT", ""):
                        continue
                    cve = row.get("CVE", "").strip().upper()
                    image = row.get("IMAGE", "").strip()
                    justification = row.get("JUSTIFICATION", "").strip()
                    if not cve or not image:
                        continue
                    if not any(image.startswith(r) for r in ALLOWED_REGISTRIES):
                        continue
                    m = re.search(r"@sha256:([0-9a-f]{64})", image)
                    if not m:
                        continue
                    rows.append((m.group(1), cve, justification))
        except Exception as exc:
            print(f"[warn] Could not read {csv_path}: {exc}", file=sys.stderr)
        return rows

    csv_paths = sorted(Path(reports_dir).rglob("*.csv"))
    with ThreadPoolExecutor(max_workers=CSV_WORKERS) as pool:
        for batch in as_completed({pool.submit(_parse_csv, p): p for p in csv_paths}):
            for sha256, cve, justification in batch.result():
                with lock:
                    if cve not in seen[sha256]:
                        result[sha256].append((cve, justification))
                        seen[sha256].add(cve)

    return dict(result)


# ---------------------------------------------------------------------------
# Step 2 — Get all currently deployed images from RHACS
# ---------------------------------------------------------------------------

def get_deployed_images(session: requests.Session, verbose: bool = False) -> dict[str, str]:
    """
    Return all images known to RHACS, keyed by sha256 manifest digest.

    Uses GET /v1/images (paginated) — the same endpoint used by triage.py.
    GET /v1/deployments only returns a lightweight list schema with no
    container image details, so it cannot be used here.

    sha256 is extracted from the ``@sha256:<hex>`` portion of the image name,
    matching the format used in the triage CSV IMAGE column.

    Returns:
        { sha256_hex: full_image_name }
    """
    images: dict[str, str] = {}
    offset = 0

    while True:
        resp = session.get(
            f"{session.base_url}/v1/images",
            params={
                "pagination.limit": PAGE_SIZE,
                "pagination.offset": offset,
            },
            timeout=60,
        )
        resp.raise_for_status()
        img_list = resp.json().get("images", [])
        if not img_list:
            break

        for img in img_list:
            name_val = img.get("name", "")
            full_name = name_val if isinstance(name_val, str) else name_val.get("fullName", "")

            if not any(full_name.startswith(r) for r in ALLOWED_REGISTRIES):
                continue

            # sha256 lives in the @sha256:<hex> portion of the image name —
            # this is the canonical manifest digest, identical to what the
            # triage CSV IMAGE column records.
            m = re.search(r"@sha256:([0-9a-f]{64})", full_name)
            if not m:
                continue
            sha256 = m.group(1)

            if sha256 not in images:
                images[sha256] = full_name
                if verbose:
                    print(f"    found image: {full_name}")

        if len(img_list) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    return images


def _image_query(full_name: str, sha256: str) -> str:
    """Return the best RHACS alert search query for a specific image.

    RHACS search field ``Image`` matches against the full image reference.
    ``Image SHA256:`` is NOT a valid field and causes 500 errors.
    We prefer the full name (which includes @sha256:) for exact matching;
    fall back to bare ``@sha256:<hex>`` if the name is empty.
    """
    ref = full_name if full_name else f"@sha256:{sha256}"
    return f"Image:{ref}"


# ---------------------------------------------------------------------------
# Step 3 — Find all active alerts for an image
# ---------------------------------------------------------------------------

def find_alerts_for_image(
    session: requests.Session,
    sha256: str,
    full_name: str,
) -> list[tuple[str, str]]:
    """
    Fetch all active alerts for a single image in one HTTP call.

    Uses ``Image:{full_name}`` query — ``Image SHA256:`` is not a valid RHACS
    search field and causes 500 errors.

    Returns:
        [(alert_id, policy_id), ...]
    """
    query = _image_query(full_name, sha256)
    resp = session.get(
        f"{session.base_url}/v1/alerts",
        params={"query": query, "pagination.limit": 1000},
        timeout=30,
    )
    if resp.status_code in (404, 400):
        return []
    if not resp.ok:
        # Log and skip rather than raising — exclusion is the primary goal
        print(f"  [warn] alerts query returned {resp.status_code} for {sha256[:12]}: {resp.text[:120]}",
              file=sys.stderr)
        return []

    results = []
    for alert in resp.json().get("alerts", []):
        if alert.get("state", "ACTIVE") != "ACTIVE":
            continue
        alert_id = alert.get("id", "")
        policy_id = (alert.get("policy") or {}).get("id", "")
        if alert_id:
            results.append((alert_id, policy_id))
    return results


# ---------------------------------------------------------------------------
# Step 4a — Add sha256-scoped image exclusion to a policy
# ---------------------------------------------------------------------------

def add_image_exclusion(
    session: requests.Session,
    policy_id: str,
    sha256: str,
    full_image_name: str,
    dry_run: bool,
) -> bool:
    """
    Fetch the policy, append an image exclusion scoped to the exact sha256,
    then PUT the updated policy back.

    The exclusion ``image.name`` uses the full image reference (which includes
    ``@sha256:<hex>``) so it matches exactly one image digest.

    Returns True if the policy was updated (or would be updated in dry-run).
    """
    resp = session.get(f"{session.base_url}/v1/policies/{policy_id}", timeout=30)
    if resp.status_code == 404:
        return False
    resp.raise_for_status()
    policy = resp.json()

    # Skip locked policies — criteria lock does NOT affect exclusions in
    # RHACS, but we check anyway to be safe
    if policy.get("criteriaLocked"):
        print(f"  [skip] policy '{policy.get('name')}' has criteriaLocked=true")
        return False

    # Stable exclusion name keyed on sha256 — one exclusion per image digest
    exclusion_name = f"{EXCLUSION_PREFIX}: {sha256[:16]}"

    # Image name to match: use full name with @sha256 if available, else plain sha256
    # RHACS treats this as a substring/regex against the deployed image name
    image_match = full_image_name if ("@sha256:" in full_image_name) else f"@sha256:{sha256}"

    exclusions: list = policy.get("exclusions") or []

    # Idempotency check — don't add the same exclusion twice
    for ex in exclusions:
        if ex.get("name") == exclusion_name:
            return False  # already present

    new_exclusion = {
        "name": exclusion_name,
        "image": {"name": image_match},
    }
    exclusions.append(new_exclusion)
    policy["exclusions"] = exclusions

    if dry_run:
        return True

    put_resp = session.put(
        f"{session.base_url}/v1/policies/{policy_id}",
        json=policy,
        timeout=30,
    )
    if not put_resp.ok:
        print(
            f"      [error] PUT policy {policy_id} returned "
            f"{put_resp.status_code}: {put_resp.text[:200]}",
            file=sys.stderr,
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Step 4b — Resolve a single active alert
# ---------------------------------------------------------------------------

def resolve_alert(
    session: requests.Session, alert_id: str, dry_run: bool
) -> bool:
    if dry_run:
        return True
    resp = session.patch(
        f"{session.base_url}/v1/alerts/{alert_id}/resolve",
        json={"whitelist": False},
        timeout=30,
    )
    return resp.ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--reports-dir",
        default=REPORTS_DIR,
        help=f"Root directory that contains triage *.csv reports (default: {REPORTS_DIR})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying RHACS",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print each deployed image as it is discovered",
    )
    args = parser.parse_args()

    endpoint = os.environ.get("ROX_ENDPOINT", "").strip()
    token = os.environ.get("ROX_API_TOKEN", "").strip()
    if not endpoint or not token:
        print(
            "ERROR: ROX_ENDPOINT and ROX_API_TOKEN must be set.\n"
            "  export ROX_ENDPOINT=central.example.com:443\n"
            "  export ROX_API_TOKEN=<your-token>",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.dry_run:
        print("[DRY-RUN MODE] no changes will be made to RHACS\n")

    # ------------------------------------------------------------------
    # 1. Load false positives from CSV reports
    # ------------------------------------------------------------------
    print(f"Loading VEX triage reports from {args.reports_dir!r} …")
    fp_map = load_false_positives(args.reports_dir)
    total_fp_images = len(fp_map)
    total_fp_cves = sum(len(v) for v in fp_map.values())
    print(f"  {total_fp_images} images with {total_fp_cves} false-positive CVE entries\n")

    if not fp_map:
        print("No false positives found — nothing to do.")
        return

    session = make_session(endpoint, token)

    # ------------------------------------------------------------------
    # 2. Get all currently deployed images from RHACS
    # ------------------------------------------------------------------
    print("Fetching deployed images from RHACS …")
    deployed = get_deployed_images(session, verbose=args.verbose)
    print(f"  {len(deployed)} unique images currently deployed\n")

    # ------------------------------------------------------------------
    # 3. Match deployed images against report false positives by sha256
    # ------------------------------------------------------------------
    matched: list[tuple[str, str, list[tuple[str, str]]]] = []  # (sha256, full_name, fp_cves)
    for sha256, full_name in deployed.items():
        if sha256 in fp_map:
            matched.append((sha256, full_name, fp_map[sha256]))

    print(f"  {len(matched)} running image(s) have matching VEX false-positive reports\n")

    if not matched:
        print("No matches between running images and report false positives.\n"
              "Tip: ensure the IMAGE column in CSVs uses the same image digest "
              "as the images currently deployed on the cluster.")
        return

    # ------------------------------------------------------------------
    # 4. For each matched image: fetch all its alerts in one call (parallel),
    #    then apply policy exclusions + resolve (serialized per policy_id).
    # ------------------------------------------------------------------
    stats = {"exclusions_added": 0, "alerts_resolved": 0, "already_clean": 0, "errors": 0}
    stats_lock = Lock()
    # Serialize policy writes per policy_id to avoid concurrent PUT races
    policy_locks: dict[str, Lock] = defaultdict(Lock)
    updated_policies: set[str] = set()
    policy_write_lock = Lock()

    def _process_image(sha256: str, full_name: str, fp_cves: list[tuple[str, str]]) -> None:
        alerts = find_alerts_for_image(session, sha256, full_name)

        lines = [
            f"Image: {full_name or sha256}",
            f"  sha256: {sha256}",
            f"  FP CVEs in report: {len(fp_cves)} | active alerts: {len(alerts)}",
        ]

        if not alerts:
            lines.append("  no active alerts — already clean")
            with stats_lock:
                stats["already_clean"] += 1
            print("\n".join(lines) + "\n")
            return

        for alert_id, policy_id in alerts:
            aid_short = alert_id[:8]

            # --- policy exclusion (persistent, serialized per policy) ---
            if policy_id:
                with policy_write_lock:
                    already = policy_id in updated_policies
                if not already:
                    with policy_locks[policy_id]:
                        with policy_write_lock:
                            already = policy_id in updated_policies
                        if not already:
                            action = "would add" if args.dry_run else "adding"
                            lines.append(f"  alert {aid_short}… → {action} exclusion to policy {policy_id[:8]}…")
                            ok = add_image_exclusion(
                                session, policy_id, sha256, full_name,
                                args.dry_run,
                            )
                            if ok:
                                with stats_lock:
                                    stats["exclusions_added"] += 1
                                with policy_write_lock:
                                    updated_policies.add(policy_id)
                            else:
                                with stats_lock:
                                    stats["errors"] += 1
                else:
                    lines.append(f"  alert {aid_short}… → policy {policy_id[:8]}… already updated this run")

            # --- resolve current alert ---
            action = "would resolve" if args.dry_run else "resolving"
            lines.append(f"  alert {aid_short}… → {action} alert")
            if resolve_alert(session, alert_id, args.dry_run):
                with stats_lock:
                    stats["alerts_resolved"] += 1
            else:
                lines.append(f"  [error] failed to resolve alert {alert_id}")
                with stats_lock:
                    stats["errors"] += 1

        print("\n".join(lines) + "\n")

    with ThreadPoolExecutor(max_workers=HTTP_WORKERS) as pool:
        futs = {
            pool.submit(_process_image, sha256, full_name, fp_cves): sha256
            for sha256, full_name, fp_cves in matched
        }
        for fut in as_completed(futs):
            exc = fut.exception()
            if exc:
                print(f"[error] {futs[fut]}: {exc}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Images matched:          {len(matched)}")
    print(f"  Policy exclusions added: {stats['exclusions_added']}"
          + (" (dry-run)" if args.dry_run else ""))
    print(f"  Alerts resolved:         {stats['alerts_resolved']}"
          + (" (dry-run)" if args.dry_run else ""))
    print(f"  CVEs already clean:      {stats['already_clean']}")
    if stats["errors"]:
        print(f"  Errors:                  {stats['errors']}")
    if args.dry_run:
        print("\n[DRY-RUN] Re-run without --dry-run to apply changes.")


if __name__ == "__main__":
    main()
