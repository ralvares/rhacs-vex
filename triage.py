import argparse
import functools
import requests
import requests_cache
from datetime import timedelta
import os
import re
import json
import time
import pandas as pd
from dataclasses import dataclass, field
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from version_utils.rpm import compare_versions
from lib4sbom.parser import SBOMParser as _SBOMParser
from rich.console import Console
from rich.table import Table
from rich import box

# --- 1. JUPYTER VIEW CONFIGURATION ---
pd.set_option('display.max_colwidth', None)
pd.set_option('display.max_rows', None)

# --- 2. CONFIGURATION & DIRECTORY SETUP ---
BASE_DIR    = "data"
VEX_DIR     = os.path.join(BASE_DIR, "vex")
SBOM_DIR    = os.path.join(BASE_DIR, "sbom")
SCAN_DIR    = os.path.join(BASE_DIR, "scans")

SCAN_FILE       = "scan.csv"
SCAN_CACHE_TTL  = 4 * 3600   # seconds; re-fetch scan after 4 hours
MAX_WORKERS     = 20

# ── Product-ID prefix helpers ────────────────────────────────────────────────

def _build_pid_name(data: dict) -> tuple[dict, dict, set]:
    """
    Build lookup maps from a VEX product tree — no hardcoded labels needed.

    Returns:
      pid_name        : {product_id → human_name}  from branch nodes
      rel_parent      : {full_component_pid → parent_product_human_name}  from relationships
      rhel_base_pids  : set of product_ids whose VEX name starts with
                        'Red Hat Enterprise Linux' — these are the RHEL base repos
                        (BaseOS, AppStream, CRB, SAP, …) as declared in the VEX tree itself
    """
    pid_name: dict = {}

    def _walk(branches):
        for b in branches:
            p = b.get('product', {})
            if p.get('product_id'):
                pid_name[p['product_id']] = p.get('name', '')
            _walk(b.get('branches', []))

    _walk(data.get('product_tree', {}).get('branches', []))

    rel_parent: dict = {}
    for rel in data.get('product_tree', {}).get('relationships', []):
        fpid   = rel.get('full_product_name', {}).get('product_id', '')
        parent = rel.get('relates_to_product_reference', '')
        if fpid and parent:
            rel_parent[fpid] = pid_name.get(parent, parent)

    # Derive RHEL base repo PIDs directly from VEX product names — no hardcoded prefixes.
    # Red Hat names every base RHEL stream product as "Red Hat Enterprise Linux <stream>".
    rhel_base_pids: set = {
        pid for pid, name in pid_name.items()
        if name.startswith('Red Hat Enterprise Linux')
    }

    return pid_name, rel_parent, rhel_base_pids


def _pid_label(pid: str, pid_name: dict, rel_parent: dict) -> str:
    """
    Return the human-readable label for a VEX product_id, taken directly
    from the VEX product tree with no abbreviation or hardcoded mapping.
    """
    if pid in rel_parent:
        return rel_parent[pid]
    parent_pid = pid.split(':')[0]
    if parent_pid in pid_name:
        return pid_name[parent_pid]
    return parent_pid


# ── WorkloadContext ───────────────────────────────────────────────────────────

@dataclass
class WorkloadContext:
    """
    Describes the workload being triaged so that VEX product-ID matching
    can be correctly scoped.

    image_ref     : original image string (may be None)
    rhel_ver      : RHEL major version as a string, e.g. "8" or "9"
    workload_type : "ubi"      – plain UBI/RHEL base image
                    "ocp"      – OpenShift platform component
                    "operator" – OpenShift operator image
    ocp_ver       : OCP major.minor, e.g. "4.14"  (ocp/operator only)
    image_ns      : registry namespace slug, e.g. "compliance"
    image_name    : image name slug, e.g. "openshift-compliance-rhel8-operator"
    extra_prefixes: additional VEX product-ID substrings to treat as "in-scope"
    """
    image_ref     : Optional[str]   = None
    rhel_ver      : str             = "8"
    workload_type : str             = "ubi"      # ubi | ocp | operator
    ocp_ver       : Optional[str]   = None
    image_ns      : Optional[str]   = None
    image_name    : Optional[str]   = None
    display_name  : str             = "UBI8"
    extra_prefixes: List[str]       = field(default_factory=list)
    # Maps binary RPM name → source RPM name (built from SBOM GENERATED_FROM rels).
    # e.g. {"python3-urllib3": "python-urllib3", "libgcc": "gcc", ...}
    # Populated by callers that have SBOM access; empty dict means no mapping.
    sbom_src_map  : dict            = field(default_factory=dict)


# Namespace → VEX prefix map loaded from data/ns_vex_prefixes.json.
# Generate it by running:  python3 build_ns_map.py
_NS_VEX_MAP_PATH = os.path.join(BASE_DIR, "ns_vex_prefixes.json")

def _load_ns_vex_map() -> dict:
    """Load the catalog-generated namespace→VEX-prefix map from JSON."""
    try:
        with open(_NS_VEX_MAP_PATH) as _fh:
            return json.load(_fh)
    except Exception:
        return {}

_NS_TO_VEX_PREFIXES = _load_ns_vex_map()


def parse_image_ref(image_ref: str) -> WorkloadContext:
    """
    Parse a Red Hat container image reference and return a WorkloadContext.

    Examples
    --------
    registry.redhat.io/compliance/openshift-compliance-rhel8-operator@sha256:...
      → WorkloadContext(rhel_ver='8', workload_type='operator',
                        image_ns='compliance', ...)

    registry.redhat.io/openshift4/ose-cli:v4.14
      → WorkloadContext(rhel_ver='8', workload_type='ocp', ocp_ver='4.14', ...)

    registry.redhat.io/ubi8/ubi:latest
      → WorkloadContext(rhel_ver='8', workload_type='ubi', ...)
    """
    ctx = WorkloadContext(image_ref=image_ref)

    # Strip registry prefix + digest/tag
    path = re.sub(r'^[^/]+/', '', image_ref)    # remove registry
    path = re.sub(r'[@:][^/]*$', '', path)      # remove tag/digest
    parts = path.split('/', 1)
    ns   = parts[0].lower() if parts else ""
    name = parts[1].lower() if len(parts) > 1 else ""

    ctx.image_ns   = ns
    ctx.image_name = name

    # ── Detect RHEL version from image name ──────────────────────────────
    rv = re.search(r'rhel(\d+)', name) or re.search(r'rhel(\d+)', ns) \
      or re.search(r'^ubi(\d+)$', ns)
    ctx.rhel_ver = rv.group(1) if rv else "8"

    # ── Detect OCP version from tag ─────────────────────────────────────
    ocp_tag = re.search(r'v(4\.\d+)', image_ref)
    if ocp_tag:
        ctx.ocp_ver = ocp_tag.group(1)

    # ── Classify workload type ───────────────────────────────────────────
    ubi_ns = re.match(r'^ubi\d+', ns) or name == "" or ns in ("ubi", "rhel")
    ocp_ns = ns in ("openshift4", "ocp4") or "ose-" in name

    if ubi_ns:
        ctx.workload_type = "ubi"
        ctx.display_name  = f"UBI{ctx.rhel_ver}"
    elif ocp_ns:
        ctx.workload_type = "ocp"
        ctx.display_name  = f"OpenShift {ctx.ocp_ver or '4.x'}"
        # OCP product scope is derived from the VEX product tree at audit time;
        # no prefixes needed here — _pid_in_scope handles it via product names.
    else:
        ctx.workload_type = "operator"
        # Always add the full registry URL prefix + short namespace prefix.
        # This covers VEX product IDs that are full image refs, e.g.:
        #   registry.redhat.io/rhacm2/multicluster-operators-subscription-rhel9@sha256:...
        registry = re.match(r'^([^/]+)/', image_ref)
        reg_host = registry.group(1) if registry else "registry.redhat.io"
        ctx.extra_prefixes.append(f"{reg_host}/{ns}/")   # full registry URL form
        ctx.extra_prefixes.append(f"{ns}/")               # short form used in some VEX trees

        # Pull in all prefix candidates from the catalog-derived map.
        # The map already includes normalised display names, OLM package names,
        # and hardcoded overrides for divergent product families (rhacm2, odf4, …).
        for ns_key, prefixes in _NS_TO_VEX_PREFIXES.items():
            if ns_key == ns or ns_key in ns or ns_key in name:
                for p in prefixes:
                    if p not in ctx.extra_prefixes:
                        ctx.extra_prefixes.append(p)

        ver_label = f" (RHEL {ctx.rhel_ver})"
        ctx.display_name = f"{ns}/{name}{ver_label}"

    return ctx


def _pid_in_scope(pid: str, ctx: WorkloadContext, pid_name: dict, rhel_base_pids: set) -> bool:
    """
    Return True if a VEX product_id is relevant to the given WorkloadContext.

    - UBI      : only RHEL base repos (derived from VEX product tree names)
    - OCP      : RHEL base repos + any product whose VEX name is
                 "Red Hat OpenShift Container Platform <version>" — version
                 matched component-wise so "4" covers all 4.x and "4.21" is exact
    - operator : RHEL base repos + catalog-derived prefixes in ctx.extra_prefixes
                 (never hardcoded here; built from data/ns_vex_prefixes.json)
    """
    if _is_rhel_base_product(pid, ctx.rhel_ver, rhel_base_pids):
        return True

    if ctx.workload_type == "ubi":
        return False

    if ctx.workload_type == "ocp":
        parent_pid  = pid.split(':')[0]
        parent_name = pid_name.get(parent_pid) or pid_name.get(pid, '')
        if 'openshift container platform' in parent_name.lower():
            if not ctx.ocp_ver:
                return True
            # Component-wise prefix match: VEX "4" covers any 4.x;
            # VEX "4.21" covers 4.21.x; VEX "4.18" does NOT match 4.21
            name_ver = parent_name.split()[-1]          # "4" or "4.21"
            c = ctx.ocp_ver.split('.')
            n = name_ver.split('.')
            return c[:len(n)] == n
        return False

    # operator: use catalog-derived prefixes only (ctx.extra_prefixes populated
    # from data/ns_vex_prefixes.json — no hardcoded strings here)
    pid_lower = pid.lower()
    for prefix in ctx.extra_prefixes:
        if prefix.lower() in pid_lower:
            return True
    return False

# Create the folder structure
os.makedirs(VEX_DIR, exist_ok=True)

# ETag-aware HTTP session for Red Hat VEX downloads.
# requests-cache handles If-None-Match / 304 responses automatically —
# no manual .etag side-files required.
_VEX_SESSION = requests_cache.CachedSession(
    cache_name=os.path.join(VEX_DIR, '.http_cache'),
    cache_control=True,   # honour ETag / Last-Modified from the Red Hat CDN
    stale_if_error=True,  # fall back to stale cache on network failure
)

# --- 3. SYNC ENGINE: Dual-Format Mirror ---

def download_and_convert_with_lib(cve_id: str) -> tuple[str, bool]:
    """Download a Red Hat VEX JSON file with automatic ETag-based caching.

    requests-cache sends If-None-Match on every request and handles 304
    responses transparently — no manual .etag files required.  The plain
    JSON is written to VEX_DIR so audit_row_detailed() can read it directly.
    """
    cve_id = cve_id.upper().strip()
    m = re.search(r'CVE-(\d{4})-', cve_id)
    if not m:
        return cve_id, False

    year      = m.group(1)
    url       = f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_id.lower()}.json"
    json_path = os.path.join(VEX_DIR, f"{cve_id}.json")
    try:
        res = _VEX_SESSION.get(url, timeout=10)
        # Write the JSON when: (a) server returned new content, or (b) the
        # json file was manually deleted while the HTTP cache still has the body.
        if res.status_code == 200 and (not res.from_cache or not os.path.exists(json_path)):
            with open(json_path, "w") as f:
                f.write(res.text)
        return cve_id, res.status_code == 200
    except Exception:
        return cve_id, os.path.exists(json_path)

# --- 4. RHACS API CLIENT ---

# CPE format:  cpe:/part:vendor:product:version:update:edition:lang
# The product token and vex-prefix mapping is handled entirely through the
# catalog-generated ns_map (data/ns_vex_prefixes.json) via parse_image_ref.
# CPE labels are parsed only to extract RHEL version, product version, and
# to build version-specific OCP RHOSE prefixes.


def parse_context_from_labels(labels: dict, image_ref: str = "") -> WorkloadContext:
    """
    Derive a WorkloadContext from Docker image labels.

    Namespace/type/vex-prefix resolution is done entirely through parse_image_ref
    (which uses the catalog-generated ns_map).  The ``cpe`` label is used only to:
      - refine the RHEL major version  (from the ``elN`` suffix)
      - attach version-specific OCP RHOSE prefixes when workload_type is "ocp"
      - update the display name with the product version

    CPE format: ``cpe:/{part}:{vendor}:{product}:{version}:{update}:{edition}:{lang}``
    """
    cpe  = labels.get("cpe", "")
    name = labels.get("name", "")   # e.g. "rhacm2/multicluster-operators-subscription-rhel9"

    # Use the name label as the primary ref for namespace resolution when available
    # (it is the clean canonical path without registry prefix or digest noise).
    ref = f"registry.redhat.io/{name}" if "/" in name else (image_ref or "")
    ctx = parse_image_ref(ref) if ref else WorkloadContext()
    # Always preserve the original image_ref for identity/digest tracking downstream.
    if image_ref:
        ctx.image_ref = image_ref

    # ── Extract version info from CPE ────────────────────────────────────
    if cpe:
        cpe_clean = re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':')
        parts = cpe_clean.split(':')
        # Indices: 0=part  1=vendor  2=product  3=version  4=update  5=edition(lang)
        version_tok = parts[3]         if len(parts) > 3 else ""
        lang_tok    = parts[5].lower() if len(parts) > 5 else ""

        # RHEL version from language field  (e.g. "el9" → "9")
        rhel_m = re.search(r'el(\d+)', lang_tok)
        if rhel_m:
            ctx.rhel_ver = rhel_m.group(1)

        # Update display name with product version from CPE
        if version_tok:
            base = ctx.display_name.split('(')[0].strip()
            ctx.display_name = f"{base} {version_tok}"

        # For OCP images: OCP product scope is derived from the VEX product tree
        # at audit time via _pid_in_scope — no prefixes to set here.
        if ctx.workload_type == "ocp" and version_tok:
            ctx.ocp_ver = version_tok

    return ctx


def _rhacs_session(endpoint: str, token: str) -> requests_cache.CachedSession:
    """Build a CachedSession pre-configured for the RHACS API.

    Image detail (/v1/images/<id>, /v1/images/scan) and SBOM responses are
    cached automatically with per-endpoint TTLs.  Search and list endpoints
    (e.g. /v1/images?query=…) are excluded from caching so cluster state is
    always fresh.
    """
    base = f"https://{endpoint}"
    s = requests_cache.CachedSession(
        cache_name=os.path.join(SCAN_DIR, '.rhacs_http_cache'),
        allowable_methods=['GET', 'POST'],
        urls_expire_after={
            f"{base}/v1/images/*":        timedelta(seconds=SCAN_CACHE_TTL),
            f"{base}/api/v1/images/sbom": timedelta(days=7),
            "*":                          requests_cache.DO_NOT_CACHE,
        },
        stale_if_error=True,
    )
    s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/json"})
    s.verify = False   # Central may use self-signed cert
    s.base_url = base  # type: ignore[attr-defined]
    return s


def rhacs_find_image(session, image_ref: str) -> Optional[str]:
    """
    Search RHACS for an image by reference and return its internal ID.
    Tries progressively shorter name forms if the full ref isn't found,
    including a cross-registry fallback using 'Image Remote:'.
    """
    bare = re.sub(r'[@:][^/]*$', '', image_ref)

    # Determine whether the caller specified a specific tag/digest
    has_tag_or_digest = bool(re.search(r'[@:]', image_ref.split('/')[-1]))
    tag_suffix = None
    if has_tag_or_digest:
        m = re.search(r'(:[^/@]+)$', image_ref)
        if m:
            tag_suffix = m.group(1)

    # Strip registry prefix (e.g. registry.access.redhat.com) for cross-registry queries.
    # A registry prefix contains a '.' in the first path component.
    bare_parts = bare.split('/', 1)
    bare_no_reg = bare_parts[1] if len(bare_parts) > 1 and '.' in bare_parts[0] else bare

    # Build queries from most specific to broadest.
    # Deduplicate in case bare == bare_no_reg (no registry prefix in image_ref).
    queries = [f'Image:{image_ref}', f'Image:{bare}']
    cross_reg_query = f'Image Remote:{bare_no_reg}'
    if bare_no_reg != bare:
        queries.append(cross_reg_query)

    all_avail: list[str] = []   # accumulated candidates for the "not found" message

    for query in queries:
        is_fallback = query != f'Image:{image_ref}'
        url = f"{session.base_url}/v1/images"
        resp = session.get(url, params={"query": query, "pagination.limit": 20}, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("images", [])
        if not results:
            continue

        # Helper: extract fullName from either string or dict form
        def _full_name(img: dict) -> str:
            n = img.get("name", "")
            return n if isinstance(n, str) else n.get("fullName", "")

        # Prefer exact digest match if available
        digest = re.search(r'@(sha256:[a-f0-9]+)', image_ref)
        if digest:
            for img in results:
                if digest.group(1) in json.dumps(img):
                    return img["id"]

        # Floating ref (no tag/digest): prefer ':latest' across all queries.
        # Don't stop at the first result set — accumulate all candidates first
        # so we can pick a ':latest' from a cross-registry query if needed.
        if not has_tag_or_digest:
            for img in results:
                if _full_name(img).endswith(":latest"):
                    return img["id"]
            # No ':latest' yet — stash and keep going to broader queries
            for img in results:
                fn = _full_name(img) or img.get("id", "?")
                if fn not in all_avail:
                    all_avail.append(fn)
            continue

        # Specific tag requested: only return if the tag actually matches.
        if is_fallback and tag_suffix:
            for img in results:
                if _full_name(img).endswith(tag_suffix):
                    return img["id"]
            # Accumulate candidates and continue to broader queries
            for img in results:
                fn = _full_name(img) or img.get("id", "?")
                if fn not in all_avail:
                    all_avail.append(fn)
            continue

        return results[0]["id"]

    # Exhausted all queries.
    # For floating refs: if we accumulated candidates but found no ':latest',
    # return the first one (best effort).
    if not has_tag_or_digest and all_avail:
        # Look up the image id for the first candidate by re-querying
        url = f"{session.base_url}/v1/images"
        resp = session.get(url, params={"query": f"Image:{all_avail[0]}", "pagination.limit": 1}, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("images", [])
        if results:
            return results[0]["id"]

    # Last resort for specific-tag refs: ask RHACS to scan the image on-demand.
    if has_tag_or_digest:
        img_data = rhacs_scan_image(session, image_ref)
        if img_data:
            return img_data.get("id")

    return None


def rhacs_scan_image(session, image_ref: str, force: bool = False,
                     retries: int = 3, retry_delay: float = 10.0) -> Optional[dict]:
    """Fetch (or trigger) a scan for an image via POST /v1/images/scan.

    RHACS returns the existing scan if it knows the image, or scans it fresh.
    A pretty-printed JSON copy is saved to data/scans/ for offline inspection.
    Pass force=True to bypass the local HTTP cache and ask RHACS to re-scan.
    Retries up to *retries* times on Timeout/ConnectionError, waiting *retry_delay*
    seconds between attempts (doubles each retry).
    """
    os.makedirs(SCAN_DIR, exist_ok=True)
    url = f"{session.base_url}/v1/images/scan"
    if force:
        session.cache.delete(urls=[url])
    delay = retry_delay
    for attempt in range(1, retries + 2):  # +1 for the initial attempt
        try:
            resp = session.post(url, json={"imageName": image_ref, "force": force}, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            if not data.get("id"):
                return None
            cache_path = _scan_cache_path(data["id"], image_ref)
            if force or not os.path.exists(cache_path):
                with open(cache_path, "w") as fh:
                    json.dump(data, fh, indent=2)
            return data
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt <= retries:
                time.sleep(delay)
                delay *= 2
                continue
            return None
        except Exception:
            return None
    return None


def _scan_cache_path(image_id: str, image_ref: str = "") -> str:
    """Return the local file path for a saved scan: data/scans/<sanitised_ref_or_id>.json"""
    name = image_ref if image_ref else image_id
    safe = re.sub(r'[^\w@:.+-]', '_', name)
    return os.path.join(SCAN_DIR, f"{safe}.json")


def rhacs_get_image(session, image_id: str, force: bool = False, image_ref: str = "",
                    retries: int = 3, retry_delay: float = 10.0) -> dict:
    """Fetch full image detail (scan + metadata) from RHACS.

    The CachedSession handles TTL-based caching (SCAN_CACHE_TTL) automatically.
    A pretty-printed JSON copy is also saved to data/scans/ for offline inspection.
    Pass force=True to invalidate the cache entry and fetch a fresh copy.
    Retries up to *retries* times on Timeout/ConnectionError, waiting *retry_delay*
    seconds between attempts (doubles each retry).
    """
    os.makedirs(SCAN_DIR, exist_ok=True)
    url = f"{session.base_url}/v1/images/{image_id}"
    if force:
        session.cache.delete(urls=[url])
    delay = retry_delay
    for attempt in range(1, retries + 2):  # +1 for the initial attempt
        try:
            resp = session.get(url, params={"stripDescription": True}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            # Keep a pretty-printed JSON copy in SCAN_DIR for offline inspection.
            cache_path = _scan_cache_path(image_id, image_ref)
            if force or not os.path.exists(cache_path):
                with open(cache_path, "w") as fh:
                    json.dump(data, fh, indent=2)
            return data
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt <= retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    raise RuntimeError("unreachable")


def _sbom_cache_path(image_ref: str) -> str:
    """Return the local cache path for an image's SBOM: data/sbom/<name+sha>.sbom"""
    # Sanitise registry/path separators but preserve the @sha256:<digest> part
    safe = re.sub(r'[^\w@:.+-]', '_', image_ref)
    return os.path.join(SBOM_DIR, f"{safe}.sbom")


def rhacs_get_sbom(session, image_ref: str, force: bool = False) -> dict:
    """Fetch SPDX 2.3 SBOM from RHACS.

    The CachedSession caches SBOM responses for 7 days automatically.
    A plain-JSON copy is also saved to data/sbom/ for offline inspection.
    Pass force=True to invalidate the cache and fetch a fresh copy.
    """
    os.makedirs(SBOM_DIR, exist_ok=True)
    url = f"{session.base_url}/api/v1/images/sbom"
    if force:
        session.cache.delete(urls=[url])
    resp = session.post(url, json={"imageName": image_ref, "force": force}, timeout=120)
    resp.raise_for_status()
    sbom = resp.json()
    # Keep a plain-JSON copy in SBOM_DIR for offline inspection.
    cache_path = _sbom_cache_path(image_ref)
    if force or not os.path.exists(cache_path):
        with open(cache_path, "w") as fh:
            json.dump(sbom, fh, indent=2)
    return sbom


def _build_sbom_src_map(sbom: dict) -> dict:
    """Build binary→source RPM name map from an SPDX SBOM dict using lib4sbom.

    lib4sbom parses the SPDX 2.3 JSON and surfaces GENERATED_FROM relationships
    as plain dicts with 'type', 'source' (binary name) and 'target' (source name)
    — no manual SPDXID indexing or dict key spelunking required.

    Example mapping produced:
      {"python3-urllib3": "python-urllib3", "openssl-libs": "openssl", ...}
    """
    try:
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        relationships: list = parser.get_relationships()
        return {
            rel["source"]: rel["target"]
            for rel in relationships
            if rel.get("type") == "GENERATED_FROM"
            and rel.get("source") and rel.get("target")
            and rel["source"] != rel["target"]
        }
    except Exception:
        # Non-fatal fallback: manual dict walking (identical to v1 behaviour)
        src_map: dict = {}
        by_id = {pkg["SPDXID"]: pkg for pkg in sbom.get("packages", [])}
        for rel in sbom.get("relationships", []):
            if rel.get("relationshipType") == "GENERATED_FROM":
                bin_pkg = by_id.get(rel["spdxElementId"])
                src_pkg = by_id.get(rel["relatedSpdxElement"])
                if bin_pkg and src_pkg:
                    bn, sn = bin_pkg.get("name", ""), src_pkg.get("name", "")
                    if bn and sn and bn != sn:
                        src_map[bn] = sn
        return src_map


def sbom_to_packages_df(sbom: dict) -> pd.DataFrame:
    """Flatten SPDX 2.3 packages into a DataFrame with name/version/purpose columns."""
    try:
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        rows = [
            {
                "NAME":    pkg.get("name", ""),
                "VERSION": pkg.get("version", ""),
                "PURPOSE": pkg.get("type", ""),
                "FILE":    pkg.get("filename", ""),
            }
            for pkg in parser.get_packages()
            if pkg.get("name")
        ]
    except Exception:
        rows = [
            {
                "NAME":    pkg.get("name", ""),
                "VERSION": pkg.get("versionInfo", ""),
                "PURPOSE": pkg.get("primaryPackagePurpose", ""),
                "FILE":    pkg.get("packageFileName", ""),
            }
            for pkg in sbom.get("packages", [])
            if pkg.get("name")
        ]
    return pd.DataFrame(rows, columns=["NAME", "VERSION", "PURPOSE", "FILE"])


def _verify_sbom_against_df(session, image_ref: str, result_df: pd.DataFrame) -> dict:
    """Fetch SPDX SBOM from RHACS and cross-check every unique component+version in result_df.
    Returns dict: matched, total, mismatched list, error."""
    try:
        sbom = rhacs_get_sbom(session, image_ref)
        # Use lib4sbom to extract package name→versions mapping
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        pkg_versions: dict = {}
        for pkg in parser.get_packages():
            name = pkg.get("name", "")
            ver  = pkg.get("version", "")
            if name:
                pkg_versions.setdefault(name, set()).add(ver)
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


def _print_sbom_summary(console: Console, sbom_s: dict) -> None:
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


def _write_output(df: pd.DataFrame, path: str, fmt: str, console: Console) -> None:
    """Write triage results to *path* in the requested format (csv or json)."""
    if fmt == "json":
        with open(path, "w") as fh:
            json.dump(df.to_dict(orient="records"), fh, indent=2, default=str)
    else:
        df.to_csv(path, index=False)
    console.print(f"  Report saved to [cyan]{path}[/cyan] [dim]({fmt})[/dim]\n")


def rhacs_list_namespace_images(session, namespace: str) -> list:
    """
    Return a list of (full_image_name, rhacs_image_id) for every unique image
    currently deployed in *namespace*.  Uses the /v1/images endpoint filtered
    by Namespace so we get the RHACS internal IDs directly.
    """
    url  = f"{session.base_url}/v1/images"
    resp = session.get(url,
                       params={"query": f"Namespace:{namespace}",
                               "pagination.limit": 1000},
                       timeout=30)
    resp.raise_for_status()
    seen: dict = {}
    for img in resp.json().get("images", []):
        # List endpoint returns name as a plain string; detail endpoint uses {"fullName":...}
        name_val  = img.get("name", "")
        full_name = name_val if isinstance(name_val, str) else name_val.get("fullName", "")
        img_id    = img.get("id", "")
        if full_name and img_id and full_name not in seen:
            seen[full_name] = img_id
    return list(seen.items())


def rhacs_to_df(image_data: dict) -> pd.DataFrame:
    """
    Flatten RHACS image scan response into the same DataFrame shape
    that the CSV path produces:
      COMPONENT, VERSION, CVE, SEVERITY, CVSS, LINK, FIXED_VERSION, ADVISORY, ADVISORY_LINK
    Rows with no CVEs are skipped.
    """
    rows = []
    for comp in (image_data.get("scan") or {}).get("components", []):
        cname   = comp.get("name", "")
        cver    = comp.get("version", "")
        fixed_c = comp.get("fixedBy", "")
        for vuln in comp.get("vulns", []):
            cve = vuln.get("cve", "")
            if not cve:
                continue
            rows.append({
                "COMPONENT":    cname,
                "VERSION":      cver,
                "CVE":          cve.upper().strip(),
                "SEVERITY":     vuln.get("severity", ""),
                "CVSS":         vuln.get("cvss", 0),
                "LINK":         vuln.get("link", ""),
                "FIXED_VERSION": vuln.get("fixedBy", "") or fixed_c,
                "ADVISORY":     "",
                "ADVISORY_LINK": "",
            })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["COMPONENT", "VERSION", "CVE", "SEVERITY", "CVSS",
                 "LINK", "FIXED_VERSION", "ADVISORY", "ADVISORY_LINK"]
    )


# --- 5. AUDIT ENGINE ---

# All CSAF/VEX flag labels that mean the product is NOT affected by the CVE.
_NOT_AFFECTED_FLAGS = {
    'vulnerable_code_not_present',
    'vulnerable_code_not_in_execute_path',
    'component_not_present',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'inline_mitigations_already_exist',
}


def _resolve_comp(comp: str, ctx) -> set:
    """Return the set of package names to try when matching VEX product IDs.

    RHACS reports binary RPM names (e.g. ``python3-urllib3``) while Red Hat
    VEX files use the *source* RPM name (e.g. ``python-urllib3``).  When the
    caller has populated ``ctx.sbom_src_map`` from the image SBOM's
    ``GENERATED_FROM`` relationships, we include the source name so the match
    succeeds without any hardcoding.
    """
    names = {comp}
    src = ctx.sbom_src_map.get(comp) if ctx.sbom_src_map else None
    if src and src != comp:
        names.add(src)
    return names


def _pid_module_stream(pid: str):
    """Return the module stream token from a PID like '…::perl:5.32', or None."""
    if '::' in pid:
        return pid.split('::', 1)[1]   # e.g. 'perl:5.32'
    return None


def _version_is_module_stream(ver: str) -> bool:
    """Return True if the version-release string indicates an RPM module stream package.

    Module-stream RPMs have '+module+' embedded in their release field, e.g.:
      1.25.10-4.module+el8.5.0+11712+ea2d2be1
    Base (non-module) packages have simple release strings like:
      423.el8_10  or  1.24.2-9.el8_10
    """
    return '+module+' in ver


def _get_vex_product(data: dict, comp: str, ctx) -> str:
    """Return a short product label (e.g. 'OCP 4.20', 'Ceph 7.1') for the
    VEX entry that matches *comp* in the given context.  Returns '' if not found.
    """
    pid_name, rel_parent, rhel_base_pids = _build_pid_name(data)

    # Scan all matched PIDs across all vulnerability entries
    labels: set = set()
    any_in_scope = False
    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        all_pids: set = set()
        for s in ('known_affected', 'fixed', 'known_not_affected'):
            all_pids.update(ps.get(s, []))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                all_pids.update(flag.get('product_ids', []))
        for pid in all_pids:
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                continue
            any_in_scope = True
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in _resolve_comp(comp, ctx) and pid in rel_parent:
                labels.add(rel_parent[pid])

    if labels:
        return ', '.join(sorted(labels))
    if any_in_scope and ctx.display_name:
        return ctx.display_name
    return ''


@functools.lru_cache(maxsize=512)
def _load_vex(cve_id: str) -> Optional[dict]:
    """Load and cache a Red Hat VEX JSON file by CVE ID.

    Cached at the module level so audit_row_detailed and _vex_product_for_row
    share the same parsed dict — a CVE affecting 20 packages is only read
    from disk once per run.
    """
    vex_path = os.path.join(VEX_DIR, f"{cve_id}.json")
    if not os.path.exists(vex_path):
        return None
    try:
        with open(vex_path) as fh:
            return json.load(fh)
    except Exception:
        return None


def _vex_product_for_row(row, ctx) -> str:
    """Thin wrapper so _get_vex_product can be used in df.apply."""
    cve  = str(row.get('CVE', '')).strip().upper()
    comp = str(row.get('COMPONENT', ''))
    data = _load_vex(cve)
    if not data:
        return ''
    try:
        return _get_vex_product(data, comp, ctx)
    except Exception:
        return ''


def _extract_sha256(ref: str):
    """Return the sha256 digest (hex string) from an image reference or VEX product_id.

    Handles two forms:
      registry/image@sha256:HEXDIGEST         (standard OCI reference)
      STREAM:registry/image@sha256:HEXDIGEST  (VEX product_id)
    Also strips optional arch suffix like _amd64 or _arm64 after the digest.
    """
    m = re.search(r'@sha256:([a-f0-9]+)', ref, re.IGNORECASE)
    return m.group(1) if m else None

def _detect_rhel_ver(version_str):
    """Extract RHEL major version number from an RPM version-release string."""
    m = re.search(r'\.el(\d+)', version_str)
    return m.group(1) if m else None

def _detect_rhel_minor(version_str):
    """Extract RHEL minor stream number from an RPM version-release string.
    e.g. '3.9.18-3.el9_4.10' → '4',  '3.9.16-1.el9_2.12' → '2',  '3.9.25-3.el9_7.1' → '7'.
    Returns None if no minor (e.g. plain 'el9' without underscore minor).
    """
    m = re.search(r'\.el\d+_(\d+)', version_str)
    return m.group(1) if m else None

def _is_rhel_base_product(pid: str, rhel_ver: str, rhel_base_pids: set) -> bool:
    """
    Return True only if the product_id belongs to a RHEL base repo for the given
    major version.  The set of qualifying parent PIDs is derived from the VEX
    product tree (products named 'Red Hat Enterprise Linux …') — no hardcoded
    stream names (AppStream, BaseOS, CRB, …) needed.
    """
    # The parent PID (first ':'-separated segment) identifies the repo/stream.
    parent_pid = pid.split(':')[0]
    if parent_pid not in rhel_base_pids and pid not in rhel_base_pids:
        return False
    # Must also be the right major version
    pid_lower = pid.lower()
    if f'enterprise_linux_{rhel_ver}' in pid_lower:
        return True
    if re.search(rf'\.el{rhel_ver}[_.\-a-z]', pid) or re.search(rf'\.el{rhel_ver}$', pid):
        return True
    if re.search(rf'^[a-zA-Z]+-{rhel_ver}[.\-]', pid):
        return True
    return False

def _is_any_rhel_ver_product(pid, rhel_ver):
    """
    Broader match: any product_id that mentions this RHEL major version,
    including middleware built on top of RHEL (JBCS, RHOSE, …).
    Used to detect fixes that exist *only* outside the base RHEL repos.
    """
    pid_lower = pid.lower()
    if f'enterprise_linux_{rhel_ver}' in pid_lower:
        return True
    if re.search(rf'\.el{rhel_ver}[_.\-a-z]', pid) or re.search(rf'\.el{rhel_ver}$', pid):
        return True
    if re.search(rf'^[a-zA-Z]+-{rhel_ver}[.\-]', pid):
        return True
    if re.search(rf'^{rhel_ver}[A-Za-z]', pid):
        return True
    return False

def _parse_pkg_from_product_id(pid):
    """
    Extract (package_name, version_release) from a VEX product_id.

    Handles two forms:
      - Simple:  red_hat_enterprise_linux_8:libarchive       → ('libarchive', None)
      - NEVRA:   AppStream-8.x:platform-python-0:3.6.8-48.el8_7.1.aarch64
                                                             → ('platform-python', '3.6.8-48.el8_7.1')
    """
    # Strip module stream suffix  e.g. "...el8.x86_64::mysql:8.0"
    pid = pid.split('::')[0]

    # Product ID is  {parent}:{component_nevra}
    # parent itself may contain colons (rare), but component never starts with a letter after the first ':'
    # Safe split: take everything after the first ':'
    colon = pid.find(':')
    if colon < 0:
        return None, None
    component_part = pid[colon + 1:]

    # NEVRA format: name-EPOCH:version-release.arch  (epoch is a digit sequence)
    epoch_match = re.search(r'-(\d+):', component_part)
    if epoch_match:
        name = component_part[:epoch_match.start()]
        rest = component_part[epoch_match.end():]   # version-release.arch
        # Strip architecture suffix
        arch_match = re.search(r'\.(aarch64|x86_64|ppc64le|s390x|i686|noarch|src)$', rest)
        if arch_match:
            rest = rest[:arch_match.start()]
        # rest is now version-release
        return name, rest

    # Simple format: just a bare package name (no epoch colon)
    # Strip any remaining arch suffix just in case
    component_part = re.sub(r'\.(aarch64|x86_64|ppc64le|s390x|i686|noarch|src)$', '', component_part)
    return component_part, None

def _summarise_vex_products(data, pid_name: dict, rel_parent: dict):
    """
    Return (affected_labels, fixed_labels, not_affected_labels, investigating_labels)
    as sorted lists of human-readable product names from a VEX document.
    Labels are derived from the VEX product tree via _pid_label — no hardcoded table.
    """
    affected, fixed, not_affected, investigating = set(), set(), set(), set()
    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        for pid in ps.get('known_affected', []):
            affected.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('fixed', []):
            fixed.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('known_not_affected', []):
            not_affected.add(_pid_label(pid, pid_name, rel_parent))
        for pid in ps.get('under_investigation', []):
            investigating.add(_pid_label(pid, pid_name, rel_parent))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                for pid in flag.get('product_ids', []):
                    not_affected.add(_pid_label(pid, pid_name, rel_parent))
    return sorted(affected), sorted(fixed), sorted(not_affected), sorted(investigating)

def audit_row_detailed(row, ctx: WorkloadContext):
    comp    = row['COMPONENT']
    found_v = str(row['VERSION'])
    cve     = row['CVE'].strip().upper()

    data = _load_vex(cve)
    if data is None:
        return pd.Series(["❌ POSITIVE", "N/A", "VEX file missing — cannot confirm fix; treat as vulnerable.", "UNKNOWN"])

    # Build product tree lookup maps — used throughout for human-readable labels
    pid_name, rel_parent, rhel_base_pids = _build_pid_name(data)

    # Extract Red Hat severity rating from threats[category=impact]
    # Values: Critical, Important, Moderate, Low  (Red Hat scale)
    # Falls back to aggregate_severity, then CVSS baseSeverity, then RHACS scan severity
    _severity = "UNKNOWN"
    _agg = data.get('document', {}).get('aggregate_severity', {}).get('text', '')
    if _agg and _agg.strip().lower() not in ('', 'none'):
        _severity = _agg.title()
    for _vuln in data.get('vulnerabilities', []):
        for _threat in _vuln.get('threats', []):
            if _threat.get('category') == 'impact' and _threat.get('details'):
                _severity = _threat['details'].title()
                break
        if _severity != "UNKNOWN":
            break
    # Last resort: CVSS baseSeverity → map to Red Hat equivalents
    if _severity == "UNKNOWN":
        for _vuln in data.get('vulnerabilities', []):
            for _score in _vuln.get('scores', []):
                _cvss = _score.get('cvss_v3') or _score.get('cvss_v2') or {}
                _base = _cvss.get('baseSeverity', '').upper()
                if _base:
                    _severity = {'CRITICAL': 'Critical', 'HIGH': 'Important',
                                 'MEDIUM': 'Moderate', 'LOW': 'Low'}.get(_base, _base.title())
                    break
            if _severity != "UNKNOWN":
                break

    # Final fallback: use RHACS-provided severity from the scan row
    if _severity in ("UNKNOWN", "None", ""):
        _rhacs_raw = str(row.get('SEVERITY', '')).strip().upper()
        # RHACS format: LOW_VULNERABILITY_SEVERITY, MODERATE_VULNERABILITY_SEVERITY, etc.
        _mapped = _RHACS_SEVERITY_MAP.get(_rhacs_raw)
        if _mapped:
            _severity = _mapped

    # Normalize final value to clean display form
    if _severity in ("UNKNOWN", "None", "", "nan"):
        _severity = "Unknown"
    # product_tree (e.g. "red_hat_products" with cpe:/a:redhat — vendor-level,
    # meaning Red Hat explicitly says NONE of their products are affected).
    _catchall_pids: set = set()
    for branch in data.get('product_tree', {}).get('branches', []):
        prod = branch.get('product', {})
        helper = prod.get('product_identification_helper') or {}
        cpe_str = str(helper.get('cpe', ''))
        # cpe:/a:redhat  →  split(':') = ['cpe', '/a', 'redhat']
        # true catch-all has ≤3 meaningful parts (no product token)
        cpe_parts = [p for p in cpe_str.split(':') if p not in ('', 'cpe', '/a', '/o', '/h')]
        if len(cpe_parts) == 1 and cpe_parts[0].lower() in ('redhat', 'red_hat'):
            pid = prod.get('product_id', '')
            if pid:
                _catchall_pids.add(pid)
    # Also always include the well-known static catch-all product ID
    _catchall_pids.add('red_hat_products')

    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        catchall_not_affected = _catchall_pids & (
            set(ps.get('known_not_affected', [])) |
            {pid
             for flag in flags
             if flag.get('label') in _NOT_AFFECTED_FLAGS
             for pid in flag.get('product_ids', [])}
        )
        if catchall_not_affected:
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                               "Red Hat Product Security states no currently supported "
                               "Red Hat product is affected by this CVE.", _severity])

    # Determine effective RHEL version: prefer context, fall back to RPM string
    rhel_ver = _detect_rhel_ver(found_v) or ctx.rhel_ver

    if not _detect_rhel_ver(found_v):
        # ── Non-RPM component (Go, npm, …) ──────────────────────────────────
        affected, fixed, not_affected, investigating = _summarise_vex_products(data, pid_name, rel_parent)
        if not affected and not fixed and not not_affected and not investigating:
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                               "Non-RPM component not tracked in VEX — vendor does not consider it affected.",
                               _severity])

        # If workload is an operator/OCP, check if the CVE is scoped to the
        # same product family — if so it IS applicable
        if ctx.workload_type != "ubi":
            # 1. Check flags that explicitly mark our product as not-affected first.
            for vuln in data.get('vulnerabilities', []):
                for flag in vuln.get('flags', []):
                    if flag.get('label') not in _NOT_AFFECTED_FLAGS:
                        continue
                    for pid in flag.get('product_ids', []):
                        if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                            continue
                        pid_sha = _extract_sha256(pid)
                        if pid_sha:
                            # sha256 image PID: only count as a match for our exact image build
                            our_sha = _extract_sha256(ctx.image_ref or "")
                            if not our_sha or pid_sha != our_sha:
                                continue
                        lbl = _pid_label(pid, pid_name, rel_parent)
                        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                                           f"Non-RPM — not affected in {ctx.display_name} ({lbl}): "
                                           f"{flag.get('label', 'flag').replace('_', ' ')}.",
                                           _severity])

            # 2. Check product_status entries for our scope.
            our_sha = _extract_sha256(ctx.image_ref or "")
            for vuln in data.get('vulnerabilities', []):
                ps = vuln.get('product_status', {})
                for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
                    for pid in ps.get(status, []):
                        if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                            continue
                        pid_sha = _extract_sha256(pid)
                        if pid_sha:
                            # sha256 image PID: require exact digest match with our image.
                            # Without this, a fixed build of a *different* image version
                            # would incorrectly mark us as FALSE POSITIVE.
                            if not our_sha or pid_sha != our_sha:
                                continue
                        lbl = _pid_label(pid, pid_name, rel_parent)
                        if status == 'under_investigation':
                            return pd.Series(["❌ POSITIVE", "N/A",
                                               f"Under investigation by Red Hat for {ctx.display_name} — treat as vulnerable until resolved.",
                                               _severity])
                        result = "❌ POSITIVE" if status == "known_affected" else \
                                 "✅ FALSE POSITIVE" if status in ("known_not_affected", "fixed") else \
                                 "❌ POSITIVE"
                        return pd.Series([result, "N/A",
                                           f"Non-RPM CVE scoped to {ctx.display_name} ({lbl}).",
                                           _severity])

        # Check for under_investigation entries even outside operator scope
        if investigating:
            return pd.Series(["❌ POSITIVE", "N/A",
                               f"Under investigation by Red Hat — treat as vulnerable until resolved. Tracked in: {', '.join(investigating[:3])}.",
                               _severity])

        # No in-scope match — decide based on what the VEX says about related products
        if not_affected and not affected and not fixed:
            parts = [f"Not affected in: {', '.join(not_affected[:3])}"]
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                               f"Non-RPM — Red Hat states not affected: {'; '.join(parts)}.",
                               _severity])
        parts = []
        if affected:     parts.append(f"Affected in: {', '.join(affected[:3])}")
        if fixed:        parts.append(f"Fixed in: {', '.join(fixed[:3])}")
        if not_affected: parts.append(f"Not affected in: {', '.join(not_affected[:3])}")
        return pd.Series(["❌ POSITIVE", "N/A",
                           f"Non-RPM — VEX tracks CVE in related products: {'; '.join(parts)}. Treat as vulnerable.",
                           _severity])

    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])

        # --- Collect NOT_AFFECTED product IDs (product_status + all not-affected flags) -----
        not_affected_ids = set(ps.get('known_not_affected', []))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                not_affected_ids.update(flag.get('product_ids', []))

        for pid in not_affected_ids:
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                continue
            # Skip module-stream-scoped PIDs (e.g. '::perl:5.32') when the
            # installed package is a base (non-module) RPM.  A PID qualified
            # with '::module:stream' only applies to packages installed from
            # that module stream; base packages have no '+module+' in their
            # version-release string.
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in _resolve_comp(comp, ctx):
                scope = ctx.display_name
                return pd.Series(["✅ FALSE POSITIVE", "N/A",
                                   f"{scope}: component known not affected (vulnerable code not present or not executable).",
                                   _severity])

        # --- FIXED versions in scope ------------------------------------------
        scoped_fixed = []
        for pid in ps.get('fixed', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, pkg_ver = _parse_pkg_from_product_id(pid)
            if pkg_name in _resolve_comp(comp, ctx) and pkg_ver:
                scoped_fixed.append(pkg_ver)

        if scoped_fixed:
            seen, unique_fixed = set(), []
            for v in scoped_fixed:
                if v not in seen:
                    seen.add(v)
                    unique_fixed.append(v)

            # ── Stream-aware comparison ──────────────────────────────────────
            # Red Hat backports fixes to older EUS/E4S minor streams with lower
            # upstream version numbers.  e.g. the RHEL 9.0 fix for python3 may
            # be at 3.9.10-4.el9_0.9 while the RHEL 9.4 fix is 3.9.18-3.el9_4.11.
            # Comparing installed 3.9.18-3.el9_4.10 >= 3.9.10-4.el9_0.9 would be
            # a false positive — they are on different version tracks.
            # Solution: when the installed package carries a minor stream marker
            # (el9_4), only compare against fixes from the same minor stream.
            installed_minor = _detect_rhel_minor(found_v)
            if installed_minor:
                same_stream = [v for v in unique_fixed
                               if _detect_rhel_minor(v) == installed_minor]
                if same_stream:
                    compare_fixes = same_stream
                else:
                    # Fix exists in other streams but the patch for THIS minor
                    # stream has not been released yet → still VULNERABLE.
                    best_ref = unique_fixed[0]
                    return pd.Series(["❌ POSITIVE", best_ref,
                                       f"{ctx.display_name} fix not yet released in el{ctx.rhel_ver}_{installed_minor} stream "
                                       f"(installed {found_v}); fixed in other streams: {best_ref}.",
                                       _severity])
            else:
                compare_fixes = unique_fixed

            for fix_v in compare_fixes:
                try:
                    if compare_versions(found_v, fix_v) >= 0:
                        return pd.Series(["✅ FALSE POSITIVE", fix_v,
                                           f"{ctx.display_name} fix backported: installed {found_v} >= {fix_v}",
                                           _severity])
                except Exception:
                    pass
            return pd.Series(["❌ POSITIVE", compare_fixes[0],
                               f"{ctx.display_name} fix available ({compare_fixes[0]}); installed {found_v} is older.",
                               _severity])

        # --- KNOWN_AFFECTED in scope ------------------------------------------
        for pid in ps.get('known_affected', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in _resolve_comp(comp, ctx):
                # Check if a fix exists outside the in-scope products (context note)
                other_products = set()
                for fpid in ps.get('fixed', []):
                    if _is_any_rhel_ver_product(fpid, rhel_ver) and not _pid_in_scope(fpid, ctx, pid_name, rhel_base_pids):
                        other_products.add(_pid_label(fpid, pid_name, rel_parent))
                if other_products:
                    ctx_str = ", ".join(sorted(other_products))
                    note = (f"Confirmed affected in {ctx.display_name}. "
                            f"Fix exists only in: {ctx_str} — not applicable to this workload.")
                else:
                    note = f"Confirmed affected in {ctx.display_name}; no fix available yet."
                return pd.Series(["❌ POSITIVE", "N/A", note, _severity])

        # --- UNDER_INVESTIGATION in scope -------------------------------------
        for pid in ps.get('under_investigation', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in _resolve_comp(comp, ctx) or _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                return pd.Series(["❌ POSITIVE", "N/A",
                                   f"Under investigation by Red Hat for {ctx.display_name} — treat as vulnerable until resolved.",
                                   _severity])

        # --- No in-scope entry — check if any other product covers it ---------
        other_vuln, other_safe = set(), set()
        for status in ('fixed', 'known_affected', 'known_not_affected'):
            for pid in ps.get(status, []):
                if _is_any_rhel_ver_product(pid, rhel_ver) and not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids):
                    if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                        continue
                    pkg_name, _ = _parse_pkg_from_product_id(pid)
                    if pkg_name in _resolve_comp(comp, ctx):
                        label = _pid_label(pid, pid_name, rel_parent)
                        if status in ('known_affected', 'fixed'):
                            other_vuln.add(label)
                        else:
                            other_safe.add(label)

        if other_safe and not other_vuln:
            ctx_str = ", ".join(sorted(other_safe))
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                               f"Red Hat states '{comp}' not affected in related products ({ctx_str}); not tracked as affected for {ctx.display_name}.",
                               _severity])
        if other_vuln:
            ctx_str = ", ".join(sorted(other_vuln))
            return pd.Series(["❌ POSITIVE", "N/A",
                               f"CVE tracked for '{comp}' in related products ({ctx_str}); no explicit clearance for {ctx.display_name} — treat as vulnerable.",
                               _severity])

        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                           f"Component '{comp}' not tracked in VEX for this CVE — vendor does not consider it affected.",
                           _severity])

    return pd.Series(["❌ POSITIVE", "N/A", "No vulnerability entries in VEX file", _severity])


# ── Display helpers (used by both single-image and namespace modes) ───────────

_SEVERITY_ORDER = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3, "Unknown": 4}

# Maps raw RHACS scan severity (enum or already-normalized) → Red Hat display form
_RHACS_SEVERITY_MAP = {
    'CRITICAL_VULNERABILITY_SEVERITY':  'Critical',
    'HIGH_VULNERABILITY_SEVERITY':      'Important',
    'IMPORTANT_VULNERABILITY_SEVERITY': 'Important',
    'MODERATE_VULNERABILITY_SEVERITY':  'Moderate',
    'MEDIUM_VULNERABILITY_SEVERITY':    'Moderate',
    'LOW_VULNERABILITY_SEVERITY':       'Low',
    'CRITICAL':  'Critical',
    'HIGH':      'Important',
    'IMPORTANT': 'Important',
    'MEDIUM':    'Moderate',
    'MODERATE':  'Moderate',
    'LOW':       'Low',
}

RESULT_STYLES = {
    "✅ FALSE POSITIVE": "bold green",
    "❌ POSITIVE":     "bold red",
}

SEVERITY_STYLES = {
    "Critical":  "bold red",
    "Important": "red",
    "Moderate":  "yellow",
    "Low":       "dim green",
    "Unknown":   "dim",
}


def _sort_and_filter_df(df: pd.DataFrame, false_only: bool = False) -> pd.DataFrame:
    """Sort audit results by priority/severity, filter to false-positives if requested."""
    cols = ['COMPONENT', 'VEX_PRODUCT', 'VERSION', 'CVE', 'SEVERITY',
            'AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION',
            'RHACS_SEVERITY', 'SEVERITY_MISMATCH']
    # Ensure all expected columns exist even on an empty DataFrame
    for col in cols:
        if col not in df.columns:
            df[col] = pd.Series(dtype=str)

    result_df = df[cols].copy()
    if result_df.empty:
        if false_only:
            result_df = result_df[result_df['AUDIT_RESULT'] == '✅ FALSE POSITIVE']
        return result_df

    def _sort_key(row):
        j, r = row['JUSTIFICATION'], row['AUDIT_RESULT']
        if '✅' in r:                                            priority = 0
        elif 'Under investigation' in j:                         priority = 4
        elif 'VEX file missing' in j or 'VEX parse error' in j: priority = 3
        else:                                                    priority = 2
        sev = _SEVERITY_ORDER.get(str(row.get('SEVERITY', 'Unknown')).split()[0].title(), 4)
        return priority * 10000 + sev * 100  # return int, not tuple, to avoid pandas 3.x expansion

    sort_series = result_df.apply(_sort_key, axis=1)
    result_df = result_df.iloc[sort_series.to_numpy().argsort()]
    if false_only:
        result_df = result_df[result_df['AUDIT_RESULT'] == '✅ FALSE POSITIVE']
    return result_df


def _render_triage_table(console: Console, result_df: pd.DataFrame, ctx) -> None:
    """Render a Rich triage table and print per-verdict counts."""
    table = Table(
        title=f"VEX Triage Report — [bold cyan]{ctx.display_name}[/bold cyan]",
        box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=True,
    )
    table.add_column("Component", style="cyan", no_wrap=True)
    table.add_column("Product", style="magenta", no_wrap=False, max_width=30)
    table.add_column("Version", style="dim")
    table.add_column("CVE", style="bold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Result", no_wrap=True)
    table.add_column("Fix Version", style="dim")
    table.add_column("Justification")

    for _, row in result_df.iterrows():
        result   = row['AUDIT_RESULT']
        severity = str(row.get('SEVERITY', 'Unknown'))
        r_style  = RESULT_STYLES.get(result, "")
        s_style  = SEVERITY_STYLES.get(severity.split()[0].title(), "dim")
        table.add_row(
            row['COMPONENT'],
            str(row.get('VEX_PRODUCT', '') or ''),
            row['VERSION'], row['CVE'],
            f"[{s_style}]{severity}[/{s_style}]",
            f"[{r_style}]{result}[/{r_style}]",
            str(row['VEX_FIX_VER']), row['JUSTIFICATION'],
        )
    console.print(table)
    counts = result_df['AUDIT_RESULT'].value_counts()
    console.print()
    for label, count in counts.items():
        style = RESULT_STYLES.get(str(label), "")
        console.print(f"  [{style}]{label}[/{style}]: [bold]{count}[/bold]")
    console.print()


def _audit_and_display(df: pd.DataFrame, ctx,
                       console: Console, *, output_path: Optional[str] = None,
                       output_fmt: str = "csv",
                       false_only: bool = False) -> pd.DataFrame:
    """Sync VEX data, run audit, render table, print summary, optionally write output file.
    Returns the annotated result DataFrame."""

    unique_cves = [c.strip().upper() for c in df['CVE'].unique()]
    cached  = sum(1 for c in unique_cves
                  if os.path.exists(os.path.join(VEX_DIR, f"{c}.json")))
    to_fetch = len(unique_cves) - cached
    if to_fetch:
        console.print(f"🔄 Syncing {to_fetch} new/updated CVEs ({cached} cached)...")
    else:
        console.print(f"✅ All {len(unique_cves)} CVEs already cached — skipping download.")
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(download_and_convert_with_lib, c): c for c in unique_cves}
        for f in as_completed(futures): pass
    if to_fetch:
        console.print(f"✅ Sync Complete in {time.time() - start_time:.2f}s.")

    console.print(f"🚀 Running Structured Audit — context: [bold cyan]{ctx.display_name}[/bold cyan]")
    # Capture RHACS scan severity before VEX audit overwrites SEVERITY
    if not df.empty:
        df['RHACS_SEVERITY'] = df['SEVERITY'].apply(
            lambda s: _RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown')
        )

    if df.empty:
        console.print("[yellow]⚠  No CVE findings to audit.[/yellow]")
        for col in ['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_PRODUCT',
                    'RHACS_SEVERITY', 'SEVERITY_MISMATCH']:
            df[col] = pd.Series(dtype=str)
    else:
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY']] = df.apply(
            lambda row: list(audit_row_detailed(row, ctx)), axis=1, result_type='expand'
        )
        df['VEX_PRODUCT'] = df.apply(lambda row: _vex_product_for_row(row, ctx), axis=1)
        df['SEVERITY_MISMATCH'] = (
            (df['RHACS_SEVERITY'] != 'Unknown') &
            (df['SEVERITY'] != df['RHACS_SEVERITY'])
        )

    result_df = _sort_and_filter_df(df, false_only)
    _render_triage_table(console, result_df, ctx)

    if output_path and output_fmt != "table":
        _write_output(result_df, output_path, output_fmt, console)

    return result_df


def _audit_silent(df: pd.DataFrame, ctx, false_only: bool = False) -> pd.DataFrame:
    """Run VEX sync + audit and return a sorted result DataFrame — no console output."""
    unique_cves = [c.strip().upper() for c in df['CVE'].unique()]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for f in as_completed({ex.submit(download_and_convert_with_lib, c): c
                               for c in unique_cves}):
            pass

    if not df.empty:
        df['RHACS_SEVERITY'] = df['SEVERITY'].apply(
            lambda s: _RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown')
        )
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY']] = df.apply(
            lambda row: list(audit_row_detailed(row, ctx)), axis=1, result_type='expand'
        )
        df['VEX_PRODUCT'] = df.apply(lambda row: _vex_product_for_row(row, ctx), axis=1)
        df['SEVERITY_MISMATCH'] = (
            (df['RHACS_SEVERITY'] != 'Unknown') &
            (df['SEVERITY'] != df['RHACS_SEVERITY'])
        )

    return _sort_and_filter_df(df, false_only)


def _fetch_and_audit(session, image_ref: str, image_id: Optional[str],
                     false_only: bool, release_ocp_ver: Optional[str] = None,
                     force: bool = False, comp_name: Optional[str] = None) -> dict:
    """
    Fetch image scan from RHACS and run a silent audit.
    image_id=None  → will search RHACS by digest first (OCP mode).
    release_ocp_ver  → when set (--ocp mode), overrides per-image CPE OCP version
                       so all components reflect the release they ship in.
    comp_name        → OCP component name (e.g. "rhel-coreos-10"); used to detect
                       RHEL version when the image URL gives no clue.
    Returns a dict with keys: found, img_ctx, os_info, result_df, error.
    """
    try:
        if image_id is None:
            # No internal ID known — use POST /v1/images/scan which returns the
            # existing scan if RHACS already knows the image, or triggers a new scan.
            image_data = rhacs_scan_image(session, image_ref, force=force)
            if not image_data:
                return {"found": False, "error": None}
        else:
            image_data = rhacs_get_image(session, image_id, force=force, image_ref=image_ref)
        labels     = (image_data.get("metadata") or {}).get("v1", {}).get("labels") or {}
        img_ctx    = parse_context_from_labels(labels, image_ref) if labels \
                     else parse_image_ref(image_ref)
        os_info    = (image_data.get("scan") or {}).get("operatingSystem", "")

        # In --ocp mode, enforce the release version for every image in the manifest.
        # All images in an OCP release are OCP components regardless of their
        # individual CPE label (some are promoted from prior minor releases).
        if release_ocp_ver:
            minor_ver = '.'.join(release_ocp_ver.split('.')[:2])  # "4.21.2" → "4.21"
            img_ctx.workload_type = "ocp"
            img_ctx.ocp_ver = minor_ver
            # Refine RHEL version: prefer os_info (e.g. "rhel:10.0"), then comp_name
            # (e.g. "rhel-coreos-10"), to avoid defaulting to "8" for RHEL 10 images.
            os_rhel = re.search(r'(?:rhel|coreos):(\d+)', os_info or '')
            if os_rhel:
                img_ctx.rhel_ver = os_rhel.group(1)
            elif comp_name:
                cn_rhel = re.search(r'(?:rhel-[^-]+-|rhel-)(\d+)$', comp_name)
                if cn_rhel:
                    img_ctx.rhel_ver = cn_rhel.group(1)
            img_ctx.display_name = f"OpenShift {release_ocp_ver}"
            img_ctx.extra_prefixes = []  # OCP scope derived from VEX tree; no hardcoded prefixes

        # Build binary→source RPM name map from SBOM GENERATED_FROM relationships.
        # Uses lib4sbom to parse the SPDX 2.3 SBOM rather than walking raw dicts.
        try:
            _sbom = rhacs_get_sbom(session, image_ref, force=force)
            img_ctx.sbom_src_map = _build_sbom_src_map(_sbom)
        except Exception:
            pass  # non-fatal; matching falls back to exact name

        img_df     = rhacs_to_df(image_data)

        if img_df.empty:
            return {"found": True, "img_ctx": img_ctx, "os_info": os_info,
                    "result_df": None, "sbom_summary": None, "error": None}

        result_df    = _audit_silent(img_df, img_ctx, false_only)
        sbom_summary = _verify_sbom_against_df(session, image_ref, result_df)
        return {"found": True, "img_ctx": img_ctx, "os_info": os_info,
                "result_df": result_df, "sbom_summary": sbom_summary, "error": None}

    except requests.RequestException as e:
        return {"found": None, "error": str(e)}


def _display_image_result(console: Console, label: str, res: dict) -> None:
    """Print per-image header, context, and triage table from a _fetch_and_audit result."""
    console.rule(f"[bold cyan]{label}[/bold cyan]")
    if res.get("error"):
        console.print(f"[bold red]❌ Error: {res['error']}[/bold red]\n")
        return
    if not res.get("found"):
        console.print("[yellow]⚠  Not found in RHACS — skipped[/yellow]\n")
        return

    img_ctx = res["img_ctx"]
    if res.get("os_info"):
        console.print(f"[bold]OS:[/bold] [cyan]{res['os_info']}[/cyan]")
    console.print(f"[bold]Context:[/bold] type=[cyan]{img_ctx.workload_type}[/cyan]  "
                  f"rhel=[cyan]{img_ctx.rhel_ver}[/cyan]  "
                  f"display=[cyan]{img_ctx.display_name}[/cyan]")
    if img_ctx.extra_prefixes:
        console.print(f"[bold]VEX scope:[/bold] {', '.join(img_ctx.extra_prefixes[:6])}")
    console.print()

    result_df = res.get("result_df")
    if result_df is None or result_df.empty:
        console.print("[dim]No findings to display.[/dim]\n")
        return

    _render_triage_table(console, result_df, img_ctx)
    sbom_s = res.get("sbom_summary")
    if sbom_s:
        _print_sbom_summary(console, sbom_s)



def main():
    # --- 6. EXECUTION PIPELINE ---

    parser = argparse.ArgumentParser(
        description="VEX triage — analyse an RHACS scan against Red Hat VEX data.\n\n"
                    "Modes:\n"
                    "  CSV mode (default):  reads a scan CSV exported from RHACS\n"
                    "  API / single image:  --image, requires ROX_ENDPOINT + ROX_API_TOKEN\n"
                    "  API / namespace:     --namespace, requires ROX_ENDPOINT + ROX_API_TOKEN\n"
                    "                       triages every unique image deployed in that namespace",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--scan",      default=None, metavar="CSV_FILE",
                        help="Path to RHACS scan CSV (overrides API mode even if env vars are set)")
    parser.add_argument("--image",     default=None, metavar="IMAGE_REF",
                        help="Container image reference. In API mode this is the image to scan.\n"
                             "In CSV mode it provides workload context for scoping.")
    parser.add_argument("--namespace", default=None, metavar="NAMESPACE",
                        help="Kubernetes namespace. Triage all images deployed in this namespace.\n"
                             "Requires ROX_ENDPOINT + ROX_API_TOKEN. Mutually exclusive with --image.")
    parser.add_argument("--ocp",       default=None, metavar="PULLSPECS_FILE",
                        help="Path to a file produced by 'oc adm release info --pullspecs'.\n"
                             "Triages every component image in the release against RHACS.\n"
                             "Requires ROX_ENDPOINT + ROX_API_TOKEN.")
    parser.add_argument("--sbom",      action="store_true", default=False,
                        help="Fetch and display the SPDX 2.3 SBOM package list for --image.\n"
                             "Equivalent to rpm -qa without accessing the running container.\n"
                             "Requires ROX_ENDPOINT + ROX_API_TOKEN + --image.")
    parser.add_argument("--show-scan",  action="store_true", default=False,
                        help="Pretty-print the raw RHACS scan for --image as a rich table.\n"
                             "Shows every component and its CVEs with severity.\n"
                             "Uses the local cache (4 h TTL) unless --force is also set.\n"
                             "Requires ROX_ENDPOINT + ROX_API_TOKEN + --image.")
    parser.add_argument("--output",    default=None, metavar="FILE",
                        help="Output file path. If omitted, no file is written.\n"
                             "Has no effect with --format table.")
    parser.add_argument("--format",    default="csv", choices=["table", "csv", "json"],
                        dest="output_fmt",
                        help="Output format: csv (default), json, or table (terminal only, no file).")
    parser.add_argument("--false-only", action="store_true", default=False,
                        help="Only show (and count) FALSE POSITIVE findings in the output.")
    parser.add_argument("--force", action="store_true", default=False,
                        help="Bypass all local caches (scan, SBOM, VEX) and re-fetch everything.\n"
                             "By default scan results are re-used for 4 hours, SBOMs indefinitely,\n"
                             "and VEX files are validated via ETag.")
    parser.add_argument("--workers", type=int, default=10, metavar="N",
                        help="Parallel image workers for --ocp / --namespace modes (default: 10).")
    args = parser.parse_args()

    if args.namespace and args.image:
        parser.error("--namespace and --image are mutually exclusive")
    if args.ocp and (args.image or args.namespace):
        parser.error("--ocp cannot be combined with --image or --namespace")

    _console = Console()

    # ── Decide which mode to use ─────────────────────────────────────────────────
    ROX_ENDPOINT  = os.environ.get("ROX_ENDPOINT", "")
    ROX_API_TOKEN = os.environ.get("ROX_API_TOKEN", "")

    use_namespace = (
        args.namespace is not None
        and bool(ROX_ENDPOINT)
        and bool(ROX_API_TOKEN)
        and args.scan is None
    )

    use_ocp = (
        args.ocp is not None
        and bool(ROX_ENDPOINT)
        and bool(ROX_API_TOKEN)
    )

    use_sbom = (
        getattr(args, 'sbom', False)
        and args.image is not None
        and bool(ROX_ENDPOINT)
        and bool(ROX_API_TOKEN)
    )

    use_show_scan = (
        getattr(args, 'show_scan', False)
        and args.image is not None
        and bool(ROX_ENDPOINT)
        and bool(ROX_API_TOKEN)
    )

    use_api = (
        args.image is not None
        and bool(ROX_ENDPOINT)
        and bool(ROX_API_TOKEN)
        and args.scan is None
        and not use_namespace
        and not use_ocp
    )

    # Suppress HTTPS certificate warnings for RHACS API calls (self-signed certs are common)
    if use_ocp or use_namespace or use_api or use_sbom or use_show_scan:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ── Build WorkloadContext (may be refined by API labels below) ────────────────
    ctx = WorkloadContext(rhel_ver="8", workload_type="ubi", display_name="UBI8")
    if args.image:
        ctx = parse_image_ref(args.image)
        _console.print(f"\n[bold]Image:[/bold] {args.image}")

    # ── SBOM mode — print package list for an image (equivalent to rpm -qa) ────────────
    if use_sbom:
        _console.print(f"[bold]Mode:[/bold] [cyan]SBOM[/cyan]  endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        try:
            session = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            _console.print(f"📦 Fetching SPDX 2.3 SBOM for [cyan]{args.image}[/cyan]...")
            sbom      = rhacs_get_sbom(session, args.image, force=getattr(args, 'force', False))
            pkgs_df   = sbom_to_packages_df(sbom)
            created   = (sbom.get("creationInfo") or {}).get("created", "")
            creators  = ", ".join((sbom.get("creationInfo") or {}).get("creators", []))
            _console.print(f"  SPDX version : [dim]{sbom.get('spdxVersion', '')}[/dim]")
            if created:
                _console.print(f"  Created      : [dim]{created}[/dim]")
            if creators:
                _console.print(f"  Tools        : [dim]{creators}[/dim]")
            _console.print(f"  Packages     : [bold]{len(pkgs_df)}[/bold]")
            _console.print()

            tbl = Table(
                title=f"SBOM Packages — [bold cyan]{args.image}[/bold cyan]",
                box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=False,
            )
            tbl.add_column("Package",  style="cyan",    no_wrap=True)
            tbl.add_column("Version",  style="dim",     no_wrap=False, max_width=40)
            tbl.add_column("Purpose",  style="magenta", no_wrap=True)
            tbl.add_column("File",     style="dim",     no_wrap=False, max_width=45)
            for _, row in pkgs_df.iterrows():
                tbl.add_row(row["NAME"], row["VERSION"], row["PURPOSE"], row["FILE"])
            _console.print(tbl)
            _console.print()
        except requests.RequestException as e:
            _console.print(f"[bold red]\u274c RHACS API error: {e}[/bold red]")
            raise SystemExit(1)
        if not use_api:
            raise SystemExit(0)

    # ── Show-scan mode — pretty-print raw RHACS scan for --image ─────────────────
    if use_show_scan:
        _console.print(f"[bold]Mode:[/bold] [cyan]Scan viewer[/cyan]  endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        try:
            session  = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            image_id = rhacs_find_image(session, args.image)
            if not image_id:
                _console.print(f"[bold red]❌ Image not found in RHACS: {args.image}[/bold red]")
                raise SystemExit(1)
            force      = getattr(args, 'force', False)
            image_data = rhacs_get_image(session, image_id, force=force, image_ref=args.image)
            scan_time  = (image_data.get("scan") or {}).get("scanTime", "")
            os_info    = (image_data.get("scan") or {}).get("operatingSystem", "")
            components = (image_data.get("scan") or {}).get("components", [])
            total_cves = sum(len(c.get("vulns", [])) for c in components)
            _console.print(f"[bold]Image  :[/bold] [cyan]{args.image}[/cyan]")
            _console.print(f"[bold]OS     :[/bold] [cyan]{os_info}[/cyan]")
            if scan_time:
                _console.print(f"[bold]Scanned:[/bold] [dim]{scan_time}[/dim]")
            _console.print(f"[bold]Found  :[/bold] [cyan]{len(components)} components[/cyan], "
                           f"[cyan]{total_cves} CVE findings[/cyan]")
            _console.print()
            tbl = Table(
                title=f"Scan — [bold cyan]{args.image}[/bold cyan]",
                box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=False,
            )
            tbl.add_column("Component",   style="cyan",       no_wrap=True)
            tbl.add_column("Version",     style="dim",        no_wrap=True, max_width=35)
            tbl.add_column("Source",      style="dim",        no_wrap=True)
            tbl.add_column("CVEs",        style="bold",       no_wrap=True, justify="right")
            tbl.add_column("Top Severity",                    no_wrap=True)
            _sev_rank = {"CRITICAL_VULNERABILITY_SEVERITY": 0, "HIGH_VULNERABILITY_SEVERITY": 1,
                         "IMPORTANT_VULNERABILITY_SEVERITY": 1, "MODERATE_VULNERABILITY_SEVERITY": 2,
                         "MEDIUM_VULNERABILITY_SEVERITY": 2, "LOW_VULNERABILITY_SEVERITY": 3}
            _sev_label = {"CRITICAL_VULNERABILITY_SEVERITY": "Critical",
                          "HIGH_VULNERABILITY_SEVERITY": "Important",
                          "IMPORTANT_VULNERABILITY_SEVERITY": "Important",
                          "MODERATE_VULNERABILITY_SEVERITY": "Moderate",
                          "MEDIUM_VULNERABILITY_SEVERITY": "Moderate",
                          "LOW_VULNERABILITY_SEVERITY": "Low"}
            for comp in sorted(components, key=lambda c: c.get("name", "")):
                vulns    = comp.get("vulns", [])
                cve_n    = len(vulns)
                top_sev  = min((v.get("severity", "LOW_VULNERABILITY_SEVERITY") for v in vulns),
                               key=lambda s: _sev_rank.get(s, 9), default="") if vulns else ""
                sev_disp = _sev_label.get(top_sev, "")
                sev_style = SEVERITY_STYLES.get(sev_disp, "dim")
                source    = comp.get("source", "")
                tbl.add_row(
                    comp.get("name", ""),
                    comp.get("version", ""),
                    source,
                    str(cve_n) if cve_n else "-",
                    f"[{sev_style}]{sev_disp}[/{sev_style}]" if sev_disp else "-",
                )
            _console.print(tbl)
            _console.print()
        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)
        if not use_api:
            raise SystemExit(0)

    # ── OCP release mode — triage every image from `oc adm release info --pullspecs` ────
    if use_ocp:
        if not os.path.exists(args.ocp):
            _console.print(f"[bold red]❌ Pullspecs file not found: {args.ocp}[/bold red]")
            raise SystemExit(1)

        # Parse: keep lines with @sha256:, skip the 'Pull From:' release payload line
        # Format:  '  component-name   quay.io/...@sha256:HEX'
        images: list = []   # list of (component_name, full_image_ref)
        seen_digests: set = set()
        _manifest_ocp_ver: Optional[str] = None
        with open(args.ocp) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('Pull From:'):
                    continue
                # Extract release version from manifest header, e.g. "Name: 4.21.2"
                nm = re.match(r'^Name:\s+(\d+\.\d+(?:\.\d+)*)', line)
                if nm and _manifest_ocp_ver is None:
                    _manifest_ocp_ver = nm.group(1)   # full version, e.g. "4.21.2"
                    continue
                m = re.match(r'^(\S+)\s+(\S+@sha256:[a-f0-9]+)', line)
                if not m:
                    continue
                comp_name, image_ref = m.group(1), m.group(2)
                _dm = re.search(r'@sha256:([a-f0-9]+)', image_ref)
                digest = _dm.group(1) if _dm else image_ref
                if digest not in seen_digests:
                    seen_digests.add(digest)
                    images.append((comp_name, image_ref))

        if not images:
            _console.print(f"[bold red]❌ No image pull specs found in {args.ocp}[/bold red]")
            _console.print("  Make sure the file was created with: oc adm release info <version> --pullspecs")
            raise SystemExit(1)

        _console.print(f"\n[bold]Mode:[/bold] [cyan]OCP release[/cyan]  "
                       f"file=[cyan]{args.ocp}[/cyan]  "
                       f"endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        _console.print(f"✅ Parsed [bold]{len(images)}[/bold] unique component image(s) from release manifest")
        _console.print()

        try:
            session = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)

            total   = len(images)
            results_map: dict = {}   # comp_name → result dict (filled as futures complete)
            not_found: list   = []

            _console.print(f"🚀 Scanning {total} images with [bold]{args.workers}[/bold] parallel workers...\n")

            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                future_to_comp = {
                    ex.submit(_fetch_and_audit, session, image_ref, None,
                              args.false_only, _manifest_ocp_ver,
                              getattr(args, 'force', False), comp_name):
                        (comp_name, image_ref)
                    for comp_name, image_ref in images
                }
                done = 0
                for future in as_completed(future_to_comp):
                    done += 1
                    comp_name, image_ref = future_to_comp[future]
                    res = future.result()
                    results_map[comp_name] = (image_ref, res)
                    status = "✅" if res.get("found") and res.get("result_df") is not None \
                             else ("⚠ " if res.get("found") is False else "❌")
                    suffix = f"  [dim]{image_ref}[/dim]" if res.get("found") is False else ""
                    _console.print(f"  [{done}/{total}] {status} {comp_name}{suffix}", highlight=False)

            _console.print()

            # Display results in original manifest order
            all_results: list = []
            for comp_name, image_ref in images:
                image_ref_stored, res = results_map.get(comp_name, (image_ref, {"found": False, "error": None}))
                _display_image_result(_console, f"{comp_name}  [dim]{image_ref_stored}[/dim]", res)
                if not res.get("found"):
                    not_found.append(comp_name)
                elif res.get("result_df") is not None:
                    r = res["result_df"].copy()
                    r["OCP_COMPONENT"] = comp_name
                    r["IMAGE"]         = image_ref_stored
                    all_results.append(r)

            _console.rule("[bold]OCP Release Summary[/bold]")
            _console.print(f"  Scanned : [bold]{total - len(not_found)}[/bold] / {total} component image(s)")
            if not_found:
                _console.print(f"  Skipped : [yellow]{len(not_found)}[/yellow] not found in RHACS")
            _console.print()

            if all_results:
                combined = pd.concat(all_results, ignore_index=True)
                counts = combined['AUDIT_RESULT'].value_counts()
                for label, count in counts.items():
                    style = RESULT_STYLES.get(label, "")
                    _console.print(f"  [{style}]{label}[/{style}]: [bold]{count}[/bold] across "
                                   f"{combined[combined['AUDIT_RESULT']==label]['OCP_COMPONENT'].nunique()} component(s)")
                _console.print()
                if args.output and args.output_fmt != "table":
                    _write_output(combined, args.output, args.output_fmt, _console)
            raise SystemExit(0)

        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)

    # ── Namespace mode — triage every image in the namespace ─────────────────────
    if use_namespace:
        _console.print(f"\n[bold]Mode:[/bold] [cyan]RHACS API / namespace[/cyan]  "
                       f"endpoint=[cyan]{ROX_ENDPOINT}[/cyan]  "
                       f"namespace=[cyan]{args.namespace}[/cyan]")
        try:
            session = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            _console.print(f"🔍 Listing images in namespace '{args.namespace}'...")
            images = rhacs_list_namespace_images(session, args.namespace)
            if not images:
                _console.print(f"[bold yellow]⚠  No images found in namespace '{args.namespace}'.[/bold yellow]")
                raise SystemExit(0)
            _console.print(f"✅ Found [bold]{len(images)}[/bold] unique image(s)")
            _console.print()

            total = len(images)
            results_map: dict = {}

            _console.print(f"🚀 Scanning {total} images with [bold]{args.workers}[/bold] parallel workers...\n")

            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                future_to_img = {
                    ex.submit(_fetch_and_audit, session, image_ref, image_id,
                              args.false_only, None, getattr(args, 'force', False)):
                        (image_ref, image_id)
                    for image_ref, image_id in images
                }
                done = 0
                for future in as_completed(future_to_img):
                    done += 1
                    image_ref, _ = future_to_img[future]
                    res = future.result()
                    results_map[image_ref] = res
                    status = "✅" if res.get("found") and res.get("result_df") is not None \
                             else ("⚠ " if res.get("found") is False else "❌")
                    _console.print(f"  [{done}/{total}] {status} {image_ref}", highlight=False)

            _console.print()

            # Display in original order
            all_results: list = []
            for image_ref, _ in images:
                res = results_map.get(image_ref, {"found": False, "error": None})
                _display_image_result(_console, image_ref, res)
                if res.get("found") and res.get("result_df") is not None:
                    r = res["result_df"].copy()
                    r["IMAGE"] = image_ref
                    all_results.append(r)

            if all_results:
                combined = pd.concat(all_results, ignore_index=True)
                _console.rule("[bold]Namespace Summary[/bold]")
                counts = combined['AUDIT_RESULT'].value_counts()
                for label, count in counts.items():
                    style = RESULT_STYLES.get(label, "")
                    _console.print(f"  [{style}]{label}[/{style}]: [bold]{count}[/bold] across "
                                   f"{combined[combined['AUDIT_RESULT']==label]['IMAGE'].nunique()} image(s)")
                _console.print()
                if args.output and args.output_fmt != "table":
                    _write_output(combined, args.output, args.output_fmt, _console)
            raise SystemExit(0)

        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)

    # ── Load scan data (single-image API mode or CSV mode) ───────────────────────
    session = None
    if use_api:
        _console.print(f"[bold]Mode:[/bold] [cyan]RHACS API[/cyan]  endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        try:
            session    = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            _force     = getattr(args, 'force', False)
            _console.print(f"📥 Fetching scan data...")
            image_data = rhacs_scan_image(session, args.image, force=_force)
            if not image_data:
                _console.print(f"[bold red]❌ Could not scan image: {args.image}[/bold red]")
                raise SystemExit(1)

            # Refine WorkloadContext from Docker labels (more authoritative than name)
            labels = (image_data.get("metadata") or {}).get("v1", {}).get("labels") or {}
            if labels:
                ctx = parse_context_from_labels(labels, args.image)

            df = rhacs_to_df(image_data)
            os_info = (image_data.get("scan") or {}).get("operatingSystem", "")
            if os_info:
                _console.print(f"[bold]OS:[/bold] [cyan]{os_info}[/cyan]")
            _console.print(f"[bold]Found:[/bold] [cyan]{len(df)} CVE findings[/cyan] across "
                           f"[cyan]{df['COMPONENT'].nunique() if len(df) else 0} components[/cyan]")

            try:
                _sbom = rhacs_get_sbom(session, args.image, force=_force)
                ctx.sbom_src_map = _build_sbom_src_map(_sbom)
            except Exception:
                pass

        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)

    else:
        # CSV mode
        scan_file = args.scan or SCAN_FILE
        if not os.path.exists(scan_file):
            _console.print(f"[bold red]❌ '{scan_file}' not found.[/bold red]")
            _console.print("  Set ROX_ENDPOINT + ROX_API_TOKEN env vars and use --image for API mode,")
            _console.print(f"  or provide a scan CSV with --scan.")
            raise SystemExit(1)
        _console.print(f"[bold]Mode:[/bold] [cyan]CSV[/cyan]  file=[cyan]{scan_file}[/cyan]")
        df = pd.read_csv(scan_file)

    # ── Show final context ────────────────────────────────────────────────────────
    _console.print(f"[bold]Context:[/bold] type=[cyan]{ctx.workload_type}[/cyan]  "
                   f"rhel=[cyan]{ctx.rhel_ver}[/cyan]  display=[cyan]{ctx.display_name}[/cyan]")
    if ctx.extra_prefixes:
        _console.print(f"[bold]VEX scope:[/bold] {', '.join(ctx.extra_prefixes[:6])}")
    _console.print()

    _out_path = args.output if args.output and args.output_fmt != "table" else None
    result_df = _audit_and_display(df, ctx, _console,
                                   output_path=_out_path,
                                   output_fmt=args.output_fmt,
                                   false_only=args.false_only)

    # ── SBOM cross-check for single-image API mode ───────────────────────────────
    if use_api and session is not None and result_df is not None and not result_df.empty:
        _console.print("🔍 Verifying component versions against SBOM...")
        sbom_s = _verify_sbom_against_df(session, args.image, result_df)
        _print_sbom_summary(_console, sbom_s)

if __name__ == "__main__":
    main()
