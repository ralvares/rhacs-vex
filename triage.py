import argparse
import functools
import requests
import requests_cache
from datetime import timedelta
import os
import re
import json
import time
import tempfile
import pandas as pd
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed
from version_utils.rpm import compare_versions as _raw_compare_versions


def compare_versions(a: str, b: str) -> int:
    """RPM version comparison with proper epoch handling.

    Epoch format: "EPOCH:VERSION-RELEASE" (e.g. "4:5.26.3-422.el8").
    If epoch is missing, it defaults to 0. Higher epoch always wins
    regardless of version-release string.
    """
    def _parse_epoch(v):
        if ':' in v:
            parts = v.split(':', 1)
            try:
                return int(parts[0]), parts[1]
            except ValueError:
                return 0, v
        return 0, v

    epoch_a, ver_a = _parse_epoch(a)
    epoch_b, ver_b = _parse_epoch(b)

    if epoch_a != epoch_b:
        return 1 if epoch_a > epoch_b else -1
    return _raw_compare_versions(ver_a, ver_b)
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
SCAN_CACHE_TTL  = 4 * 3600   # seconds; HTTP-level re-fetch after 4 hours
LOCAL_CACHE_TTL = 24 * 3600  # seconds; re-use local JSON/SBOM files for 24 hours
MAX_WORKERS     = 20

# ── Product-ID prefix helpers ────────────────────────────────────────────────

def _build_pid_name(data: dict) -> tuple[dict, dict, set, dict, dict, dict]:
    """
    Build lookup maps from a VEX product tree — no hardcoded labels needed.
    Memoized inside the (lru-cached) VEX dict itself so the product tree is
    walked once per CVE instead of once per finding row.

    Returns:
      pid_name        : {product_id → human_name}  from branch nodes
      rel_parent      : {full_component_pid → parent_product_human_name}  from relationships
      rhel_base_pids  : set of product_ids whose VEX name starts with
                        'Red Hat Enterprise Linux' — these are the RHEL base repos
                        (BaseOS, AppStream, CRB, SAP, …) as declared in the VEX tree itself
      pid_purl        : {product_id → purl_string}  from product_identification_helper.
                        Red Hat VEX uses purl type to distinguish RPMs (pkg:rpm/redhat/…)
                        from non-RPM platform components (pkg:generic/redhat/…, e.g. rhcos).
      vex_ns_map      : {registry_namespace → set_of_parent_product_ids}  derived dynamically
                        from OCI purls in the VEX product tree.  Maps registry namespaces
                        (e.g. "rhbk") to VEX product family IDs (e.g. "red_hat_build_of_keycloak")
                        so operator images can be scoped to the correct VEX product even when
                        the static ns_vex_prefixes.json mapping is incomplete.
      pid_cpe         : {product_id → cpe_string}  from product_identification_helper.
                        Maps parent product IDs to their CPE strings so that _pid_in_scope
                        can match image CPE labels against VEX product tree CPEs.
    """
    cached = data.get('__pid_maps__')
    if cached is not None:
        return cached

    pid_name: dict = {}
    pid_purl: dict = {}
    pid_cpe: dict = {}

    def _walk(branches):
        for b in branches:
            p = b.get('product', {})
            pid = p.get('product_id')
            if pid:
                pid_name[pid] = p.get('name', '')
                helper = p.get('product_identification_helper') or {}
                purl = helper.get('purl', '')
                if purl:
                    pid_purl[pid] = purl
                cpe = helper.get('cpe', '')
                if cpe:
                    pid_cpe[pid] = cpe
            _walk(b.get('branches', []))

    _walk(data.get('product_tree', {}).get('branches', []))

    rel_parent: dict = {}
    # Also build component → parent_pid mapping for namespace discovery
    comp_to_parent_pid: dict = {}
    for rel in data.get('product_tree', {}).get('relationships', []):
        fpid   = rel.get('full_product_name', {}).get('product_id', '')
        parent = rel.get('relates_to_product_reference', '')
        comp   = rel.get('product_reference', '')
        if fpid and parent:
            rel_parent[fpid] = pid_name.get(parent, parent)
        if comp and parent:
            comp_to_parent_pid[comp] = parent

    # Derive RHEL base repo PIDs directly from VEX product names — no hardcoded prefixes.
    rhel_base_pids: set = {
        pid for pid, name in pid_name.items()
        if name.startswith('Red Hat Enterprise Linux')
    }

    # Build dynamic namespace → product family map from OCI purls.
    # For each OCI component, extract the registry namespace from its purl
    # and map it to the parent product family.
    vex_ns_map: dict = {}
    for comp_pid, purl in pid_purl.items():
        if not purl.startswith('pkg:oci/'):
            continue
        m = re.search(r'repository_url=[^/]+/([^/&]+)', purl)
        if not m:
            continue
        oci_ns = m.group(1).lower()
        parent_pid = comp_to_parent_pid.get(comp_pid)
        if parent_pid:
            vex_ns_map.setdefault(oci_ns, set()).add(parent_pid)
            # Also add the CPE product token for broader matching
            cpe = pid_cpe.get(parent_pid, '')
            if cpe:
                cpe_parts = cpe.replace('cpe:/', '').split(':')
                if len(cpe_parts) > 2:
                    vex_ns_map[oci_ns].add(cpe_parts[2])

    result = (pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe)
    data['__pid_maps__'] = result
    return result


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
    # SBOM package inventory: {name → set(versions)}.  Populated alongside
    # sbom_src_map when SBOM is available; empty dict means no SBOM loaded.
    sbom_packages : dict            = field(default_factory=dict)
    # OCP manifest component name (e.g. "etcd", "apiserver-network-proxy").
    # Set from the release manifest in --ocp mode.  Used to match VEX image-
    # level PIDs (e.g. "openshift4/ose-etcd-rhel9") for Non-RPM Go modules.
    ocp_component : Optional[str]   = None
    # Raw CPE label from the container image (e.g. "cpe:/a:redhat:openshift:4.12::el8").
    # Used for CPE-based matching against VEX product tree CPEs in _pid_in_scope.
    cpe           : Optional[str]   = None


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
    ocp_ns = ns in ("openshift4", "openshift", "ocp4", "openshift-release-dev") \
          or "ose-" in name or name.startswith("ocp-")

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
        # The map includes normalised display names, OLM package names,
        # and relatedImage namespaces — no hardcoded strings here.
        for ns_key, prefixes in _NS_TO_VEX_PREFIXES.items():
            if ns_key == ns or ns_key in ns:
                for p in prefixes:
                    if p not in ctx.extra_prefixes:
                        ctx.extra_prefixes.append(p)

        ver_label = f" (RHEL {ctx.rhel_ver})"
        ctx.display_name = f"{ns}/{name}{ver_label}"

    return ctx


def _cpe_prefix_match(image_cpe: str, vex_cpe: str) -> bool:
    """Return True if the image CPE matches the VEX product CPE as a prefix.

    CPE format: cpe:/part:vendor:product:version:update:edition:lang
    The VEX CPE may be less specific (e.g. "cpe:/a:redhat:openshift:4")
    while the image CPE is more specific (e.g. "cpe:/a:redhat:openshift:4.12::el8").

    Matching: split both into components, skip empty trailing components in
    the VEX CPE, and check that the image CPE starts with the same components.
    """
    def _parse_cpe(cpe: str) -> list:
        # Normalize: strip "cpe:/" or "cpe:2.3:" prefix
        cpe = re.sub(r'^cpe:[/\d.]*:*', '', cpe).strip(':')
        return [p for p in cpe.split(':')]

    img_parts = _parse_cpe(image_cpe)
    vex_parts = _parse_cpe(vex_cpe)

    # Strip trailing empty components from VEX CPE (e.g. "::el8" → keep vendor,product,version)
    while vex_parts and vex_parts[-1] == '':
        vex_parts.pop()
    if not vex_parts:
        return False

    # Must match at least part:vendor:product (first 3 components)
    if len(vex_parts) < 3 or len(img_parts) < 3:
        return False

    # Component-wise prefix match: each non-empty VEX component must match
    for i, vex_comp in enumerate(vex_parts):
        if i >= len(img_parts):
            return False
        if not vex_comp:
            # Empty VEX component is a wildcard (matches anything)
            continue
        # Version component: prefix match (VEX "4" matches image "4.12")
        if i == 3:  # version position
            img_ver_parts = img_parts[i].split('.')
            vex_ver_parts = vex_comp.split('.')
            if img_ver_parts[:len(vex_ver_parts)] != vex_ver_parts:
                return False
        elif vex_comp.lower() != img_parts[i].lower():
            return False
    return True


def _pid_in_scope(pid: str, ctx: WorkloadContext, pid_name: dict, rhel_base_pids: set,
                   vex_ns_map: Optional[dict] = None,
                   pid_cpe: Optional[dict] = None) -> bool:
    """
    Return True if a VEX product_id is relevant to the given WorkloadContext.

    - UBI      : only RHEL base repos (derived from VEX product tree names)
    - OCP      : RHEL base repos + any product whose VEX name is
                 "Red Hat OpenShift Container Platform <version>" — version
                 matched component-wise so "4" covers all 4.x and "4.21" is exact.
                 Also checks CPE from image labels against VEX product tree CPEs.
    - operator : RHEL base repos + catalog-derived prefixes in ctx.extra_prefixes
                 (built from data/ns_vex_prefixes.json) + dynamic VEX-derived
                 namespace→product mapping from OCI purls/CPEs in the VEX product tree

    Results are memoized per (workload identity, pid) in a cache carried by
    the per-CVE vex_ns_map — the same pid is checked thousands of times per
    image across statuses, flags, threats and remediations.
    """
    # Single-workload memo slot: hits repeat heavily within one image
    # (statuses, flags, threats, remediations check the same pids), so cache
    # per-pid verdicts only for the CURRENT workload and wipe on change.
    # Keeps memory at O(pids) per CVE instead of O(pids × images).
    _cache = None
    _key = pid
    if isinstance(vex_ns_map, dict):
        _fp = (ctx.workload_type, ctx.rhel_ver, ctx.ocp_ver, ctx.image_ns,
               ctx.image_name, ctx.ocp_component, ctx.cpe,
               tuple(ctx.extra_prefixes))
        _slot = vex_ns_map.get('__scope_cache__')
        if _slot is None or _slot[0] != _fp:
            _slot = (_fp, {})
            vex_ns_map['__scope_cache__'] = _slot
        _cache = _slot[1]
        _hit = _cache.get(_key)
        if _hit is not None:
            return _hit

    def _memo(result: bool) -> bool:
        if _cache is not None:
            _cache[_key] = result
        return result

    if _is_rhel_base_product(pid, ctx.rhel_ver, rhel_base_pids):
        return _memo(True)

    if ctx.workload_type == "ubi":
        return _memo(False)

    if ctx.workload_type == "ocp":
        parent_pid  = pid.split(':')[0]
        parent_name = pid_name.get(parent_pid) or pid_name.get(pid, '')
        if 'openshift container platform' in parent_name.lower():
            # Default to OCP 4 when version unknown (openshift4/ images are 4.x)
            effective_ver = ctx.ocp_ver or "4"
            # Component-wise prefix match: VEX "4" covers any 4.x;
            # VEX "4.21" covers 4.21.x; VEX "4.18" does NOT match 4.21
            name_ver = parent_name.split()[-1]          # "4" or "4.21"
            c = effective_ver.split('.')
            n = name_ver.split('.')
            return _memo(c[:len(n)] == n)
        # CPE-based matching: when the image has a CPE label, check it
        # against the VEX parent product's CPE for structural matching.
        if pid_cpe and ctx.cpe:
            vex_parent_cpe = pid_cpe.get(parent_pid, '')
            if vex_parent_cpe and _cpe_prefix_match(ctx.cpe, vex_parent_cpe):
                return _memo(True)
        # OCP images pull RPMs from multiple repos (Fast Datapath, etc.)
        # — any product matching the RHEL version is in scope.
        if _is_any_rhel_ver_product(pid, ctx.rhel_ver):
            return _memo(True)
        return _memo(False)

    # operator: catalog-derived prefixes (ctx.extra_prefixes from ns_vex_prefixes.json)
    # + dynamic VEX-derived namespace→product mapping from OCI purls/CPEs
    pid_lower = pid.lower()
    for prefix in ctx.extra_prefixes:
        if prefix.lower() in pid_lower:
            return _memo(True)
    # Dynamic: check if the VEX product tree maps the operator's registry
    # namespace to this PID's parent product via OCI purl data
    if vex_ns_map and ctx.image_ns:
        parent_pid = pid.split(':')[0]
        ns_products = vex_ns_map.get(ctx.image_ns.lower(), set())
        if parent_pid in ns_products:
            return _memo(True)
        # Also check CPE product token match
        for prod_id in ns_products:
            if prod_id.lower() in pid_lower:
                return _memo(True)
    return _memo(False)

# Create the folder structure
os.makedirs(VEX_DIR, exist_ok=True)

# ETag-aware HTTP session for Red Hat VEX downloads.
# requests-cache handles If-None-Match / 304 responses automatically —
# no manual .etag side-files required.
_VEX_SESSION = requests_cache.CachedSession(
    cache_name=os.path.join(VEX_DIR, '.http_cache'),
    cache_control=True,   # honour ETag / Last-Modified from the Red Hat CDN
    stale_if_error=True,  # fall back to stale cache on network failure
    backend='sqlite',
    wal=True,
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
            fd, tmp = tempfile.mkstemp(dir=VEX_DIR, suffix='.tmp')
            try:
                with os.fdopen(fd, 'w') as f:
                    f.write(res.text)
                os.replace(tmp, json_path)
            except Exception:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        return cve_id, res.status_code == 200
    except requests.RequestException:
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

    # Store raw CPE label for downstream CPE-based matching
    if cpe:
        ctx.cpe = cpe

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

        # CPE product is exactly "openshift" → promote to OCP
        # (not openshift_gitops, openshift_logging, etc. — those are separate products)
        cpe_product = parts[2].lower() if len(parts) > 2 else ""
        if ctx.workload_type == "operator" and cpe_product == "openshift":
            ctx.workload_type = "ocp"
            ctx.display_name = f"OpenShift {version_tok or ctx.ocp_ver or '4.x'}"
            ctx.extra_prefixes = []
            if version_tok:
                ctx.ocp_ver = version_tok

    # Derive ocp_component from the image name label when available.
    # e.g. "openshift4/ose-etcd-rhel9" → "etcd"
    if ctx.workload_type == "ocp" and name and not ctx.ocp_component:
        ctx.ocp_component = _normalize_vex_image_core(name)

    # The pulled image reference is authoritative for the RHEL variant —
    # Brew labels can lag a rebuild (label says rhel8, registry path rhel9).
    if image_ref:
        ref_base = re.sub(r'[@:][^/]*$', '', image_ref).split('/')[-1]
        rm = re.search(r'rhel(\d+)', ref_base)
        if rm:
            ctx.rhel_ver = rm.group(1)

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
        backend='sqlite',
        wal=True,
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
            return n if isinstance(n, str) else (n.get("fullName", "") if n else "")

        # Prefer exact digest match if available
        digest = re.search(r'@(sha256:[a-f0-9]+)', image_ref)
        if digest:
            for img in results:
                if digest.group(1) in json.dumps(img):
                    return img["id"]
            continue

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
    A JSON copy is saved to data/scans/ and reused on subsequent calls within
    LOCAL_CACHE_TTL (24 h) to avoid redundant RHACS round-trips.
    Pass force=True to bypass all caches and re-scan from scratch.
    Retries up to *retries* times on Timeout/ConnectionError, waiting *retry_delay*
    seconds between attempts (doubles each retry).
    """
    os.makedirs(SCAN_DIR, exist_ok=True)

    # Check local file cache first (keyed by image_ref which contains the SHA).
    ref_cache = _scan_cache_path("", image_ref)
    if not force and _local_cache_fresh(ref_cache, image_ref):
        try:
            with open(ref_cache) as fh:
                return json.load(fh)
        except Exception:
            pass

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
            fd, tmp = tempfile.mkstemp(dir=SCAN_DIR, suffix='.tmp')
            with os.fdopen(fd, 'w') as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, cache_path)
            return data
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt <= retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code >= 500 and attempt <= retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise
    return None


def _scan_cache_path(image_id: str, image_ref: str = "") -> str:
    """Return the local file path for a saved scan: data/scans/<sanitised_ref_or_id>.json"""
    name = image_ref if image_ref else image_id
    safe = re.sub(r'[^\w@:.+-]', '_', name)
    return os.path.join(SCAN_DIR, f"{safe}.json")


def _local_cache_fresh(path: str, image_ref: str = "") -> bool:
    """Return True when the cached copy at *path* is still usable.

    Digest-pinned references (@sha256:) are content-addressed — the image can
    never change, so a cached scan/SBOM for it is valid forever.  This keeps
    re-runs from hammering RHACS Central for images it has already scanned.
    Tag/floating references keep the LOCAL_CACHE_TTL window.
    """
    try:
        if '@sha256:' in (image_ref or ''):
            return os.path.getsize(path) > 0
        age = time.time() - os.path.getmtime(path)
        return age < LOCAL_CACHE_TTL
    except OSError:
        return False


def rhacs_get_image(session, image_id: str, force: bool = False, image_ref: str = "",
                    retries: int = 3, retry_delay: float = 10.0) -> dict:
    """Fetch full image detail (scan + metadata) from RHACS.

    A JSON copy is saved to data/scans/ and reused within LOCAL_CACHE_TTL (24 h).
    Pass force=True to bypass all caches and fetch a fresh copy.
    Retries up to *retries* times on Timeout/ConnectionError, waiting *retry_delay*
    seconds between attempts (doubles each retry).
    """
    os.makedirs(SCAN_DIR, exist_ok=True)

    cache_path = _scan_cache_path(image_id, image_ref)
    if not force and _local_cache_fresh(cache_path, image_ref):
        try:
            with open(cache_path) as fh:
                return json.load(fh)
        except Exception:
            pass

    url = f"{session.base_url}/v1/images/{image_id}"
    if force:
        session.cache.delete(urls=[url])
    delay = retry_delay
    for attempt in range(1, retries + 2):  # +1 for the initial attempt
        try:
            resp = session.get(url, params={"stripDescription": True}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            fd, tmp = tempfile.mkstemp(dir=SCAN_DIR, suffix='.tmp')
            with os.fdopen(fd, 'w') as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, cache_path)
            return data
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt <= retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code >= 500 and attempt <= retries:
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

    A JSON copy is saved to data/sbom/ and reused within LOCAL_CACHE_TTL (24 h).
    Pass force=True to bypass all caches and fetch a fresh copy.
    """
    os.makedirs(SBOM_DIR, exist_ok=True)

    cache_path = _sbom_cache_path(image_ref)
    if not force and _local_cache_fresh(cache_path, image_ref):
        try:
            with open(cache_path) as fh:
                return json.load(fh)
        except Exception:
            pass

    url = f"{session.base_url}/api/v1/images/sbom"
    if force:
        session.cache.delete(urls=[url])
    resp = session.post(url, json={"imageName": image_ref, "force": force}, timeout=120)
    resp.raise_for_status()
    sbom = resp.json()
    fd, tmp = tempfile.mkstemp(dir=SBOM_DIR, suffix='.tmp')
    with os.fdopen(fd, 'w') as fh:
        json.dump(sbom, fh, indent=2)
    os.replace(tmp, cache_path)
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
        by_id = {pkg.get("SPDXID"): pkg for pkg in sbom.get("packages", []) if pkg.get("SPDXID")}
        for rel in sbom.get("relationships", []):
            if rel.get("relationshipType") == "GENERATED_FROM":
                bin_pkg = by_id.get(rel.get("spdxElementId"))
                src_pkg = by_id.get(rel.get("relatedSpdxElement"))
                if bin_pkg and src_pkg:
                    bn, sn = bin_pkg.get("name", ""), src_pkg.get("name", "")
                    if bn and sn and bn != sn:
                        src_map[bn] = sn
        return src_map


def _build_sbom_packages(sbom: dict) -> dict:
    """Build {name → set(versions)} from an SPDX SBOM for per-row verification."""
    pkgs: dict = {}
    try:
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        for pkg in parser.get_packages():
            name = pkg.get("name", "")
            ver = pkg.get("version", "")
            if name:
                pkgs.setdefault(name, set()).add(ver)
    except Exception:
        for pkg in sbom.get("packages", []):
            name = pkg.get("name", "")
            ver = pkg.get("versionInfo", "")
            if name:
                pkgs.setdefault(name, set()).add(ver)
    return pkgs


def _sbom_note(comp: str, version: str, ctx) -> str:
    """Return SBOM verification fragment for an OS/RPM component.

    Uses RPM version comparison (compare_versions) to relate the scanner-
    reported version against the SBOM inventory.  Only produces output when
    sbom_packages is populated.  Returns '' when SBOM is unavailable.
    """
    if not ctx.sbom_packages:
        return ''
    names = _resolve_comp(comp, ctx)
    for name in names:
        sbom_vers = ctx.sbom_packages.get(name)
        if sbom_vers is None:
            continue
        # Find the highest SBOM version via RPM comparison
        sbom_list = sorted(sbom_vers)
        best_sbom = sbom_list[0]
        for sv in sbom_list[1:]:
            try:
                i, f = _normalize_epoch(sv, best_sbom)
                if compare_versions(i, f) > 0:
                    best_sbom = sv
            except Exception:
                pass
        # Compare scanner version against best SBOM version
        try:
            cmp_scan, cmp_sbom = _normalize_epoch(version, best_sbom)
            cmp = compare_versions(cmp_scan, cmp_sbom)
        except Exception:
            cmp = None
        if cmp == 0:
            return f"{comp}-{version} (SBOM verified)"
        elif cmp is not None and cmp > 0:
            return f"{comp}-{version} (scanner reports newer than SBOM: {best_sbom})"
        elif cmp is not None and cmp < 0:
            return f"{comp}-{version} (SBOM has newer: {best_sbom})"
        return f"{comp}-{version} (SBOM has: {best_sbom})"
    return f"{comp}-{version} (not in SBOM)"


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
    seen: set = set()
    for comp in (image_data.get("scan") or {}).get("components", []):
        cname   = comp.get("name", "")
        cver    = comp.get("version", "")
        fixed_c = comp.get("fixedBy", "")
        for vuln in comp.get("vulns", []):
            cve = vuln.get("cve", "")
            if not cve:
                continue
            key = (cname, cver, cve.upper().strip())
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "COMPONENT":    cname,
                "VERSION":      cver,
                "CVE":          cve.upper().strip(),
                "SEVERITY":     vuln.get("severity") or "",
                "CVSS":         vuln.get("cvss") or 0,
                "LINK":         vuln.get("link") or "",
                "FIXED_VERSION": vuln.get("fixedBy", "") or fixed_c,
                "SOURCE":       comp.get("source", ""),
                "LOCATION":     comp.get("location", ""),
                "ADVISORY":     "",
                "ADVISORY_LINK": "",
            })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["COMPONENT", "VERSION", "CVE", "SEVERITY", "CVSS",
                 "LINK", "FIXED_VERSION", "SOURCE", "LOCATION",
                 "ADVISORY", "ADVISORY_LINK"]
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

    Bridges naming differences between RHACS scan components and Red Hat VEX:
      - RPM binary→source: ``python3-urllib3`` → ``python-urllib3`` (via SBOM)
      - Maven groupId:artifactId → bare artifactId: VEX PIDs use the Maven
        artifact name (e.g. ``nimbus-jose-jwt``), while RHACS reports the full
        coordinate (``com.nimbusds:nimbus-jose-jwt``).
    """
    names = {comp}
    src = ctx.sbom_src_map.get(comp) if ctx.sbom_src_map else None
    if src and src != comp:
        names.add(src)
    # Maven groupId:artifactId → extract bare artifactId.
    # VEX uses bare artifact name as PID (e.g. "nimbus-jose-jwt"),
    # RHACS reports "com.nimbusds:nimbus-jose-jwt".
    # Guard: must have ':' but NOT '/' (avoid Go module paths or image refs).
    if ':' in comp and '/' not in comp and not comp.startswith('cpe:'):
        artifact = comp.rsplit(':', 1)[-1]
        if artifact and artifact != comp:
            names.add(artifact)
    return names


def _src_alias_names(data: dict, comp: str, found_v: str) -> set:
    """Source-RPM aliases for a binary package, derived from the VEX itself.

    Red Hat VEX often tracks only the source package (ceph, perl) while the
    scanner reports binary subpackages (ceph-mon, perl-libs).  A .src NEVRA
    whose version-release exactly equals the installed component's — and whose
    name is a dash-prefix of the component name — is the source that built it.
    Purely data-driven; no name lists.
    """
    src_vr = data.get('__src_vr__')
    if src_vr is None:
        src_vr = {}
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for st in ('known_affected', 'fixed', 'known_not_affected',
                       'under_investigation'):
                for pid in ps.get(st, []):
                    base = pid.split('::')[0]
                    if not base.endswith('.src'):
                        continue
                    name, vr = _parse_pkg_from_product_id(pid)
                    if name:
                        # vr is None for version-less product-level PIDs
                        # (red_hat_ceph_storage:ceph.src) — record as wildcard.
                        src_vr.setdefault(name, set()).add(vr)
        data['__src_vr__'] = src_vr
    vr = found_v.split(':', 1)[-1] if ':' in found_v else found_v
    out = set()
    for src, vrs in src_vr.items():
        if comp.startswith(src + '-') and (vr in vrs or None in vrs):
            out.add(src)
    return out


def _normalize_vex_image_core(img: str) -> str:
    """Extract the OCP component core name from a VEX image-style PID component.

    'openshift4/ose-etcd-rhel9'                          -> 'etcd'
    'openshift4/ose-machine-config-operator'              -> 'machine-config-operator'
    'openshift4/ose-cluster-etcd-rhel8-operator'          -> 'cluster-etcd-operator'
    'openshift4/ose-docker-builder-rhel9'                 -> 'docker-builder'
    'openshift4/ose-agent-installer-api-server-rhel9'     -> 'agent-installer-api-server'
    """
    if '/' in img:
        img = img.split('/', 1)[1]
    if img.startswith('ose-'):
        img = img[4:]
    img = re.sub(r'-rhel\d+', '', img)
    img = re.sub(r'--+', '-', img).strip('-')
    return img


def _extract_rhel_from_vex_image(img: str) -> Optional[str]:
    """Extract RHEL major version from a VEX image PID, or None if absent."""
    m = re.search(r'-rhel(\d+)', img)
    return m.group(1) if m else None


# OCP component name ↔ VEX generic component name normalization.
# RHCOS ships as a bare VEX PID (pkg:generic/redhat/rhcos), not as an
# ose-* image-path PID like other OCP components.  The OCP release manifest
# names it "rhel-coreos-10" (with RHEL version suffix); VEX calls it "rhcos".
_OCP_GENERIC_ALIASES = {'rhcos': 'rhel-coreos'}


def _normalize_ocp_component(name: str) -> str:
    """Normalize OCP manifest / VEX generic component names for matching.

    Handles the well-known RHCOS alias and strips trailing RHEL version:
      'rhcos'           → 'rhel-coreos'   (VEX generic name → expanded)
      'rhel-coreos-10'  → 'rhel-coreos'   (OCP manifest name → base form)
      'rhel-coreos-9'   → 'rhel-coreos'
      'etcd'            → 'etcd'          (unchanged)
    """
    name = name.lower()
    if name in _OCP_GENERIC_ALIASES:
        return _OCP_GENERIC_ALIASES[name]
    # Strip trailing RHEL version suffix from OCP component names like rhel-coreos-10.
    # Anchored to rhel-coreos pattern to avoid mangling unrelated components.
    name = re.sub(r'^(rhel-coreos)-\d+$', r'\1', name)
    return name


def _build_image_purl(image_ref: Optional[str], image_name_label: Optional[str] = None):
    """Build OCI identity candidates for the image.

    Returns (candidates, sha) where candidates is a list of
    (repository_url, image_name) pairs derived from:
      1. the image reference — authoritative, it is what the cluster pulls
         and what VEX purls use for registry.redhat.io images
      2. the image's `name` label — Brew metadata whose namespace/suffix may
         differ from the registry path (openshift/ vs openshift4/,
         managed-open-data-hub/ vs rhoai/)
    No namespace rewriting: the caller matches by exact repository_url first
    and falls back to purl package-name equality.
    """
    candidates = []
    sha = None
    if image_ref:
        m = re.search(r'@sha256:([a-f0-9]+)', image_ref)
        sha = m.group(1) if m else None
        bare = re.sub(r'[@:][^/]*$', '', image_ref)
        parts = bare.split('/')
        if len(parts) >= 2:
            candidates.append((bare, parts[-1]))
    if image_name_label and '/' in image_name_label:
        name = image_name_label.split('/')[-1]
        repo = f"registry.redhat.io/{image_name_label}"
        if all(c[0] != repo for c in candidates):
            candidates.append((repo, name))
    return candidates, sha


def _purl_matched_leaf_pids(pid_purl: dict, candidates: list) -> set:
    """VEX component PIDs whose OCI purl matches one of the image candidates.

    Exact repository_url match wins; when no repo matches, fall back to purl
    package-name equality — this bridges Brew label namespaces to registry
    namespaces without any hardcoded mapping.
    """
    if not candidates:
        return set()
    repos = {c[0] for c in candidates}
    names = {c[1] for c in candidates}
    by_repo, by_name = set(), set()
    for pid, purl in pid_purl.items():
        if not purl.startswith('pkg:oci/'):
            continue
        r = re.search(r'repository_url=([^&]+)', purl)
        if r and r.group(1) in repos:
            by_repo.add(pid)
            continue
        m = re.match(r'pkg:oci/([^?@]+)', purl)
        if m and m.group(1) in names:
            by_name.add(pid)
    return by_repo if by_repo else by_name


def _image_vex_lookup(ctx: WorkloadContext, data: dict,
                      pid_name: dict, rhel_base_pids: set,
                      pid_purl: Optional[dict] = None,
                      vex_ns_map: Optional[dict] = None,
                      pid_cpe: Optional[dict] = None):
    """Check VEX image-level and generic-component entries for OCP/operator workloads.

    Matches the workload's identity against VEX PIDs using:
      1. OCI purl matching (exact, from image ref/labels)
      2. String normalization fallback (for PIDs without purls)
      3. Generic component PIDs: rhcos (purl pkg:generic/...)

    Returns (verdict, pid, extra, family_assessed) or None.
    Verdicts: POSITIVE, FALSE_POSITIVE, POSITIVE_OTHER_RHEL, NOT_LISTED.
    """
    if pid_purl is None:
        pid_purl = {}

    # Build image identity candidates for direct matching against the VEX
    # product tree (exact repository_url first, purl-name fallback).
    _label_name = None
    if ctx.image_ns and ctx.image_name:
        _label_name = f"{ctx.image_ns}/{ctx.image_name}"
    _candidates, _image_sha = _build_image_purl(ctx.image_ref, _label_name)
    _purl_matched_pids = _purl_matched_leaf_pids(pid_purl, _candidates)

    # Also match PIDs that contain our exact image SHA digest.
    # VEX has SHA-specific PIDs like "8Base-RHOSE-4.15:openshift4/ose-cli@sha256:34ae..."
    # When we have the SHA from ctx.image_ref, match it directly.
    # We add the parsed leaf form (pid_pkg) since downstream _matches() checks
    # pid_pkg membership, not the raw stream-prefixed PID.
    if _image_sha:
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
                for pid in ps.get(status, []):
                    pid_sha = _extract_sha256(pid)
                    if pid_sha and pid_sha == _image_sha:
                        _leaf, _ = _parse_pkg_from_product_id(pid)
                        if _leaf:
                            _purl_matched_pids.add(_leaf)

    if ctx.workload_type == "ocp":
        comp = ctx.ocp_component or (
            _normalize_vex_image_core(ctx.image_name) if ctx.image_name else None)
        if not comp:
            return None
        _comp_normalized = _normalize_ocp_component(comp)
        def _matches(pid_pkg):
            # Purl match first (exact)
            if pid_pkg in _purl_matched_pids:
                return True
            # String normalization fallback
            if '/' in pid_pkg:
                return _normalize_vex_image_core(pid_pkg) == comp
            return _normalize_ocp_component(pid_pkg) == _comp_normalized
    elif ctx.workload_type == "operator":
        if not ctx.image_name:
            return None
        def _matches(pid_pkg):
            if pid_pkg in _purl_matched_pids:
                return True
            return pid_pkg.split('/')[-1] == ctx.image_name
    else:
        return None

    def _is_generic_component(pid_pkg: str) -> bool:
        """Return True if the VEX PID package is a generic (non-RPM) component."""
        purl = pid_purl.get(pid_pkg, '')
        return purl.startswith('pkg:generic/')

    # Match specificity tiers (Red Hat VEX semantics):
    #   2 = PID carries OUR exact image digest — assessment of THIS build,
    #       overrides everything else (e.g. generic known_affected + our-SHA
    #       known_not_affected means our build contains the fix).
    #   1 = generic PID (no digest) or same-image PID for another build —
    #       stream-level evidence, weighed by RHEL-version quality.
    matches = []       # (status, pid, rhel_quality, flag_label, specificity)
    family_assessed = False

    def _pid_specificity(pid: str):
        """Return 2 when the PID carries our exact image digest, else 1."""
        pid_sha = _extract_sha256(pid)
        if pid_sha and _image_sha and pid_sha == _image_sha:
            return 2
        return 1

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        flags = vuln.get('flags', [])

        flag_map = {}
        for flag in flags:
            lbl = flag.get('label', '')
            for pid in flag.get('product_ids', []):
                flag_map[pid] = lbl

        for status in ('known_not_affected', 'known_affected', 'fixed', 'under_investigation'):
            for pid in ps.get(status, []):
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    continue
                pid_pkg, _ = _parse_pkg_from_product_id(pid)
                if not pid_pkg:
                    continue
                has_path = '/' in pid_pkg
                is_generic = not has_path and _is_generic_component(pid_pkg)
                # Image-path PIDs and generic components are eligible for matching.
                # Bare RPM PIDs (pkg:rpm/...) are handled by the RPM audit path.
                if not has_path and not is_generic:
                    continue
                if has_path:
                    family_assessed = True
                spec = _pid_specificity(pid)
                if not _matches(pid_pkg):
                    continue
                # Generic PIDs only set family_assessed when they actually match,
                # to avoid NOT_LISTED → FALSE POSITIVE for unrelated generics.
                if is_generic:
                    family_assessed = True
                pid_rhel = _extract_rhel_from_vex_image(pid_pkg)
                rhel_q = 2 if pid_rhel == ctx.rhel_ver else (1 if pid_rhel is None else 0)
                matches.append((status, pid, rhel_q, flag_map.get(pid, ''), spec))

        for flag in flags:
            if flag.get('label') not in _NOT_AFFECTED_FLAGS:
                continue
            for pid in flag.get('product_ids', []):
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    continue
                pid_pkg, _ = _parse_pkg_from_product_id(pid)
                if not pid_pkg:
                    continue
                has_path = '/' in pid_pkg
                is_generic = not has_path and _is_generic_component(pid_pkg)
                if not has_path and not is_generic:
                    continue
                if has_path:
                    family_assessed = True
                spec = _pid_specificity(pid)
                if not _matches(pid_pkg):
                    continue
                if is_generic:
                    family_assessed = True
                pid_rhel = _extract_rhel_from_vex_image(pid_pkg)
                rhel_q = 2 if pid_rhel == ctx.rhel_ver else (1 if pid_rhel is None else 0)
                if not any(p == pid and s == 'known_not_affected' for s, p, _, _, _ in matches):
                    matches.append(('known_not_affected', pid, rhel_q, flag.get('label', ''), spec))

    # SHA-exact assessments override generic ones: when VEX assessed our
    # exact build, use only those entries for the verdict.
    if any(m[4] == 2 for m in matches):
        matches = [m for m in matches if m[4] == 2]

    if not matches:
        # ── Red Hat errata policy ──────────────────────────────────────────
        # "Unless explicitly stated as not affected, all previous versions
        # of packages in any minor update stream of a product listed here
        # should be assumed vulnerable, although may not have been subject
        # to full analysis."
        #
        # Applied here: when no broad product match exists for the current
        # OCP version, check version-specific OCP streams (RHOSE-4.xx).
        #  • Current version OLDER than fixed → "previous version" → POSITIVE
        #  • Current version NEWER than fixed → NOT a "previous version" →
        #    FALSE POSITIVE (policy only assumes previous versions vulnerable)
        #  • Current version EQUALS fixed → fixed in this stream → FALSE POSITIVE
        if not family_assessed and ctx.workload_type == "ocp" and ctx.ocp_ver:
            cur_parts = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
            fixed_ocp_vers: set = set()
            affected_ocp_vers: set = set()
            for vuln in data.get('vulnerabilities', []):
                ps = vuln.get('product_status', {})
                for pid in ps.get('fixed', []):
                    m = re.search(r'RHOSE[.-](\d+\.\d+)', pid)
                    if m:
                        fixed_ocp_vers.add(m.group(1))
                for pid in ps.get('known_affected', []):
                    m = re.search(r'RHOSE[.-](\d+\.\d+)', pid)
                    if m:
                        affected_ocp_vers.add(m.group(1))
            if fixed_ocp_vers:
                newest_fix = max(fixed_ocp_vers,
                                key=lambda v: [int(x) for x in v.split('.')])
                fix_parts = [int(x) for x in newest_fix.split('.')]
                if cur_parts == fix_parts:
                    return ('FALSE_POSITIVE', '', f'errata_fixed:{newest_fix}', False)
                if fix_parts < cur_parts:
                    return ('FALSE_POSITIVE', '', f'errata_not_previous:{newest_fix}', False)

        return ('NOT_LISTED', '', '', True) if family_assessed else None

    # OCP uses RHEL-version quality scoring; operators always have quality 2
    best_quality = max(m[2] for m in matches)
    if best_quality == 0:
        aff = [(s, p, fl) for s, p, q, fl, _sp in matches
               if s in ('known_affected', 'under_investigation')]
        if aff:
            return ('POSITIVE_OTHER_RHEL', aff[0][1], aff[0][2], family_assessed)
        return ('NOT_LISTED', '', '', True) if family_assessed else None

    candidates = [(s, p, fl) for s, p, q, fl, _sp in matches if q >= max(best_quality, 1)]
    if not candidates:
        return ('NOT_LISTED', '', '', True) if family_assessed else None

    has_affected = any(s in ('known_affected', 'under_investigation') for s, _, _ in candidates)
    if has_affected:
        pid_match = next(p for s, p, _ in candidates if s in ('known_affected', 'under_investigation'))
        status = next(s for s, _, _ in candidates if s in ('known_affected', 'under_investigation'))

        # ── Errata policy override for generic product-level PIDs ─────
        # A generic known_affected PID (e.g. "…platform_4:rhcos" with no
        # RHOSE-4.xx stream) catches ALL OCP 4.x versions.  When version-
        # specific fixed entries exist (RHOSE-4.16 … 4.20), an OCP version
        # NEWER than the newest fixed stream is not a "previous version"
        # per Red Hat errata policy and should be FALSE POSITIVE.
        if ctx.workload_type == "ocp" and ctx.ocp_ver:
            affected_has_stream = any(
                re.search(r'RHOSE[.-]\d+\.\d+', p)
                for s, p, q, fl, _sp in matches
                if s in ('known_affected', 'under_investigation')
            )
            if not affected_has_stream:
                cur_parts = [int(x) for x in ctx.ocp_ver.split('.') if x.isdigit()]
                cur_minor = '.'.join(str(x) for x in cur_parts[:2])
                fixed_ocp_vers = set()
                for vuln in data.get('vulnerabilities', []):
                    ps = vuln.get('product_status', {})
                    for fpid in ps.get('fixed', []):
                        fm = re.search(r'RHOSE[.-](\d+\.\d+)', fpid)
                        if fm:
                            fixed_ocp_vers.add(fm.group(1))
                if fixed_ocp_vers:
                    if cur_minor in fixed_ocp_vers:
                        return ('FALSE_POSITIVE', pid_match,
                                f'errata_fixed:{cur_minor}', family_assessed)
                    newest_fix = max(fixed_ocp_vers,
                                    key=lambda v: [int(x) for x in v.split('.')])
                    fix_parts = [int(x) for x in newest_fix.split('.')]
                    if fix_parts < cur_parts:
                        return ('FALSE_POSITIVE', pid_match,
                                f'errata_not_previous:{newest_fix}', family_assessed)

        return ('POSITIVE', pid_match, status, family_assessed)

    has_clear = any(s in ('known_not_affected', 'fixed') for s, _, _ in candidates)
    if has_clear:
        pid_match = next(p for s, p, _ in candidates if s in ('known_not_affected', 'fixed'))
        flag_lbl = next((fl for s, _, fl in candidates if s in ('known_not_affected', 'fixed') and fl), '')
        return ('FALSE_POSITIVE', pid_match, flag_lbl, family_assessed)

    return ('NOT_LISTED', '', '', True) if family_assessed else None


def _pid_module_stream(pid: str):
    """Return the module stream token from a PID like '…::perl:5.32', or None."""
    if '::' in pid:
        return pid.split('::', 1)[1]   # e.g. 'perl:5.32'
    return None


def _version_is_module_stream(ver: str) -> bool:
    """Return True if the version-release string indicates an RPM module stream package.

    Module-stream RPMs have '.module+' in their release field, e.g.:
      1.25.10-4.module+el8.5.0+11712+ea2d2be1
    Base (non-module) packages have simple release strings like:
      423.el8_10  or  1.24.2-9.el8_10
    """
    return '.module+' in ver or '+module+' in ver


def _get_vex_product(data: dict, comp: str, ctx) -> str:
    """Return a short product label (e.g. 'OCP 4.20', 'Ceph 7.1') for the
    VEX entry that matches *comp* in the given context.  Returns '' if not found.
    """
    pid_name, rel_parent, rhel_base_pids, _pid_purl, vex_ns_map, _pid_cpe = _build_pid_name(data)

    # Scan all matched PIDs across all vulnerability entries
    labels: set = set()
    any_in_scope = False
    for vuln in data.get('vulnerabilities', []):
        ps    = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        all_pids: set = set()
        for s in ('known_affected', 'fixed', 'known_not_affected', 'under_investigation'):
            all_pids.update(ps.get(s, []))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                all_pids.update(flag.get('product_ids', []))
        for pid in all_pids:
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=_pid_cpe):
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


@functools.lru_cache(maxsize=int(os.environ.get('VEX_CACHE_SIZE', '512')))
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
    except FileNotFoundError:
        return None
    except Exception as exc:
        import logging
        logging.warning("Corrupt VEX file %s: %s — deleting to allow re-download", vex_path, exc)
        try:
            os.unlink(vex_path)
        except OSError:
            pass
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


def _normalize_epoch(installed: str, fix: str) -> tuple[str, str]:
    """Align epoch prefixes so compare_versions is not fooled by epoch mismatch.
    VEX fixed versions often omit the epoch even though the RPM carries one.
    Since both strings describe the same source package, the epoch is identical —
    propagate the present epoch to the string that lacks it.
    """
    inst_m = re.match(r'^(\d+):', installed)
    fix_m  = re.match(r'^(\d+):', fix)
    if inst_m and not fix_m:
        fix = f"{inst_m.group(1)}:{fix}"
    elif fix_m and not inst_m:
        installed = f"{fix_m.group(1)}:{installed}"
    return installed, fix


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
    """Extract RHEL major version number from an RPM version-release string.
    Handles both base RPMs (e.g. '2.28-151.el8') and module-stream RPMs
    (e.g. '4.3.1-1.module+el8.4.0+11822+6cc1e7d7').
    """
    m = re.search(r'[.+]el(\d+)', version_str)
    return m.group(1) if m else None

def _detect_rhel_minor(version_str):
    """Extract RHEL minor stream number from an RPM version-release string.

    Standard:     '3.9.18-3.el9_4.10'         → '4'
    Module:       '2.4.37-64.module+el8.10.0+' → '10'
    No minor:     '3.6.8-59.el8'              → None
    """
    # Standard format: .el9_4 or .el8_10
    m = re.search(r'\.el\d+_(\d+)', version_str)
    if m:
        return m.group(1)
    # Module stream format: +el8.10.0+ (minor is second component)
    m = re.search(r'[.+]el(\d+)\.(\d+)\.', version_str)
    if m:
        return m.group(2)
    return None

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

def _is_version_neutral_product(pid: str) -> bool:
    """True when the PID carries no RHEL/el version marker at all.

    Product-level PIDs like red_hat_openshift_container_platform_4:openshift-clients
    are version-agnostic — they cannot contradict the workload's RHEL version,
    so they are admissible as related-product evidence.
    """
    if re.search(r'[.+]el\d', pid):
        return False
    if re.search(r'_rhel_?\d', pid.lower()):
        return False
    if 'enterprise_linux_' in pid.lower():
        return False
    return True


def _is_any_rhel_ver_product(pid, rhel_ver):
    """
    Broader match: any product_id that mentions this RHEL major version,
    including middleware built on top of RHEL (JBCS, RHOSE, …).
    Used to detect fixes that exist *only* outside the base RHEL repos.
    """
    pid_lower = pid.lower()
    if f'enterprise_linux_{rhel_ver}' in pid_lower:
        return True
    if f'_rhel_{rhel_ver}' in pid_lower or f'_rhel{rhel_ver}' in pid_lower:
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

def _build_pid_severity_map(data: dict) -> dict:
    """Build {product_id: severity_title} from per-product VEX threats.
    Memoized inside the VEX dict — built once per CVE."""
    cached = data.get('__pid_severity__')
    if cached is not None:
        return cached
    pid_severity = {}
    for vuln in data.get('vulnerabilities', []):
        for threat in vuln.get('threats', []):
            if threat.get('category') != 'impact' or not threat.get('details'):
                continue
            det = threat['details'].title()
            for tpid in threat.get('product_ids', []):
                pid_severity[tpid] = det
    data['__pid_severity__'] = pid_severity
    return pid_severity


def _resolve_base_severity(data, comp, ctx, pid_name, rhel_base_pids,
                            vex_ns_map, pid_severity, row,
                            pid_cpe: Optional[dict] = None,
                            pid_purl: Optional[dict] = None) -> str:
    """Resolve VEX severity through a multi-level priority chain.

    Priority: OCI purl match > image-level PID (generic, no SHA) >
    RPM purl match > component-name PID >
    in-scope known_affected/fixed PID > aggregate_severity > generic threat >
    CVSS baseSeverity > RHACS scan severity.
    """
    severity = "UNKNOWN"
    names_to_match = _resolve_comp(comp, ctx)

    # 0. OCI purl match — highest priority for container triage.
    #    When we can match the image's OCI purl against a VEX PID's purl,
    #    use that PID's threat severity directly.
    if pid_purl and ctx.workload_type in ("ocp", "operator"):
        _label_name = None
        if ctx.image_ns and ctx.image_name:
            _label_name = f"{ctx.image_ns}/{ctx.image_name}"
        _candidates, _img_sha = _build_image_purl(ctx.image_ref, _label_name)

        def _leaf_severity(_pid):
            # pid_purl keys are component-level (leaf) PIDs, but pid_severity
            # keys are stream-prefixed relationship PIDs.  Check direct match
            # first, then any severity PID ending with :<component_pid>.
            if _pid in pid_severity:
                return pid_severity[_pid]
            for _spid, _sev in pid_severity.items():
                if _spid.endswith(':' + _pid):
                    return _sev
            return None

        # Digest-specific severities describe individual builds.  Priority:
        #   1. our own digest — authoritative for this build
        #   2. generic (no-digest) PID — Red Hat's current per-image rating
        #   3. other builds of the same image, but only when they all agree —
        #      a uniform rating across every listed build is the image's
        #      rating; mixed ratings are ambiguous and skipped.
        _matched = _purl_matched_leaf_pids(pid_purl, _candidates)
        _own = [p for p in _matched
                if _img_sha and _img_sha in p]
        _generic = [p for p in _matched if '@sha256:' not in p]
        for _pid in _own + _generic:
            _sev = _leaf_severity(_pid)
            if _sev:
                severity = _sev
                break
        if severity == "UNKNOWN":
            _other_sevs = {s for s in
                           (_leaf_severity(p) for p in _matched
                            if '@sha256:' in p and p not in _own)
                           if s}
            if len(_other_sevs) == 1:
                severity = _other_sevs.pop()

    # 1. Image-level PID severity (generic, no SHA) — most specific for
    #    container triage (e.g. openshift4/ose-cli carries per-image impact).
    if severity == "UNKNOWN" and ctx.workload_type in ("ocp", "operator"):
        img_comp = ctx.ocp_component or (
            _normalize_vex_image_core(ctx.image_name) if ctx.image_name else None)
        if img_comp:
            img_norm = _normalize_ocp_component(img_comp)
            for pid, sev in pid_severity.items():
                if '@sha256:' in pid:
                    continue
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    continue
                tpkg, _ = _parse_pkg_from_product_id(pid)
                if not tpkg:
                    continue
                if '/' in tpkg and _normalize_vex_image_core(tpkg) == img_comp:
                    severity = sev
                    break
                if '/' not in tpkg and _normalize_ocp_component(tpkg) == img_norm:
                    severity = sev
                    break

    # 2. Component-name match.
    if severity == "UNKNOWN":
        for pid, sev in pid_severity.items():
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            tpkg, _ = _parse_pkg_from_product_id(pid)
            if tpkg and tpkg in names_to_match:
                severity = sev
                break

    # 3. In-scope known_affected/fixed PID severity (pick highest).
    if severity == "UNKNOWN":
        aff_sevs = set()
        for vuln in data.get('vulnerabilities', []):
            for st in ('known_affected', 'fixed'):
                for pid in vuln.get('product_status', {}).get(st, []):
                    if pid in pid_severity and _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                        aff_sevs.add(pid_severity[pid])
        if aff_sevs:
            sev_order = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3}
            severity = min(aff_sevs, key=lambda s: sev_order.get(s, 9))

    # 4. Aggregate severity from document header.
    if severity == "UNKNOWN":
        agg = data.get('document', {}).get('aggregate_severity', {}).get('text', '')
        if agg and agg.strip().lower() not in ('', 'none'):
            severity = agg.title()

    # 5. Generic threat impact (any unscoped threat entry).
    if severity == "UNKNOWN":
        for vuln in data.get('vulnerabilities', []):
            for threat in vuln.get('threats', []):
                if threat.get('category') == 'impact' and threat.get('details'):
                    severity = threat['details'].title()
                    break
            if severity != "UNKNOWN":
                break

    # 6. CVSS baseSeverity.
    if severity == "UNKNOWN":
        for vuln in data.get('vulnerabilities', []):
            for score in vuln.get('scores', []):
                cvss = score.get('cvss_v3') or score.get('cvss_v2') or {}
                base = cvss.get('baseSeverity', '').upper()
                if base:
                    severity = {'CRITICAL': 'Critical', 'HIGH': 'Important',
                                'MEDIUM': 'Moderate', 'LOW': 'Low'}.get(base, base.title())
                    break
            if severity != "UNKNOWN":
                break

    # 7. RHACS scan severity (last resort).
    if severity in ("UNKNOWN", "None", ""):
        rhacs_raw = str(row.get('SEVERITY', '')).strip().upper()
        mapped = _RHACS_SEVERITY_MAP.get(rhacs_raw)
        if mapped:
            severity = mapped

    if severity in ("UNKNOWN", "None", "", "nan"):
        severity = "Unknown"

    return severity


def _is_catchall_not_affected(data: dict) -> bool:
    """True if a vendor-level catch-all PID marks all products as not-affected.

    Detects vendor-level PIDs (e.g. "red_hat_products" with cpe:/a:redhat)
    and checks if they appear in known_not_affected or not-affected flags.
    """
    catchall_pids: set = set()
    for branch in data.get('product_tree', {}).get('branches', []):
        prod = branch.get('product', {})
        helper = prod.get('product_identification_helper') or {}
        cpe_str = str(helper.get('cpe', ''))
        cpe_parts = [p for p in cpe_str.split(':') if p not in ('', 'cpe', '/a', '/o', '/h')]
        if len(cpe_parts) == 1 and cpe_parts[0].lower() in ('redhat', 'red_hat'):
            pid = prod.get('product_id', '')
            if pid:
                catchall_pids.add(pid)
    catchall_pids.add('red_hat_products')

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        flags = vuln.get('flags', [])
        catchall_not_affected = catchall_pids & (
            set(ps.get('known_not_affected', [])) |
            {pid
             for flag in flags
             if flag.get('label') in _NOT_AFFECTED_FLAGS
             for pid in flag.get('product_ids', [])}
        )
        if catchall_not_affected:
            return True
    return False


def _audit_nonrpm(comp, found_v, data, ctx, pid_name, rel_parent,
                   rhel_base_pids, pid_purl, vex_ns_map, severity, row,
                   pid_cpe: Optional[dict] = None):
    """Audit a non-RPM component (Go, npm, Python, image ref).

    Called when the installed version has no .elN marker.  Non-RPM components
    cannot be matched by RPM version comparison, so the audit relies on
    image-level VEX entries, flags, and product-status scoping.

    Returns pd.Series([verdict, fix, justification, severity]).
    """
    affected, fixed, not_affected, investigating = _summarise_vex_products(
        data, pid_name, rel_parent)

    # ── No VEX data at all for any product ──────────────────────────────
    if not affected and not fixed and not not_affected and not investigating:
        return pd.Series(["⚠️ NOT ASSESSED", "N/A",
                           "Non-RPM component not tracked in VEX.", severity])

    # ── OCP/operator: image-level and scoped matching ───────────────────
    if ctx.workload_type != "ubi":

        # 0. Image-level VEX matching (identity-based, not package-name).
        if ctx.workload_type in ("ocp", "operator"):
            img_result = _image_vex_lookup(
                ctx, data, pid_name, rhel_base_pids, pid_purl, vex_ns_map,
                pid_cpe=pid_cpe)
            if img_result is not None:
                verdict, pid_match, extra, _fam = img_result
                if pid_match:
                    lbl = _pid_label(pid_match, pid_name, rel_parent)
                    pid_pkg = pid_match.split(':', 1)[1] if ':' in pid_match else pid_match
                    img_lbl = f"{lbl} — {pid_pkg}" if pid_pkg not in lbl else lbl
                else:
                    img_lbl = ctx.display_name

                if verdict == 'FALSE_POSITIVE':
                    if extra and extra.startswith('errata_'):
                        _tag, fixed_in_ver = extra.split(':', 1)
                        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                            f"Fixed in OCP {fixed_in_ver}.", severity])
                    flag_desc = f" ({extra.replace('_', ' ')})" if extra else ""
                    return pd.Series(["✅ FALSE POSITIVE", "N/A",
                        f"known_not_affected{flag_desc}. {img_lbl}.", severity])
                elif verdict == 'POSITIVE':
                    vex_status = extra if extra in (
                        'known_affected', 'under_investigation', 'fixed') else 'known_affected'
                    if vex_status == 'under_investigation':
                        return pd.Series(["❌ POSITIVE", "N/A",
                            f"under_investigation. {img_lbl}.", severity])
                    return pd.Series(["❌ POSITIVE", "N/A",
                        f"{vex_status}. {img_lbl}.", severity])
                elif verdict == 'POSITIVE_OTHER_RHEL':
                    return pd.Series(["❌ POSITIVE", "N/A",
                        f"known_affected for different RHEL ({img_lbl}).", severity])
                elif verdict == 'NOT_LISTED':
                    comp_ref = ctx.ocp_component or ctx.display_name
                    return pd.Series(["✅ FALSE POSITIVE", "N/A",
                        f"{comp_ref} not listed as affected.", severity])

        # 1. Flags that explicitly mark our product as not-affected.
        is_image_comp = '/' in comp
        for vuln in data.get('vulnerabilities', []):
            for flag in vuln.get('flags', []):
                if flag.get('label') not in _NOT_AFFECTED_FLAGS:
                    continue
                for pid in flag.get('product_ids', []):
                    if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                        continue
                    pid_sha = _extract_sha256(pid)
                    if pid_sha:
                        our_sha = _extract_sha256(ctx.image_ref or "")
                        if not our_sha or pid_sha != our_sha:
                            continue
                    elif is_image_comp and _is_rhel_base_product(
                            pid, ctx.rhel_ver, rhel_base_pids):
                        continue
                    else:
                        flag_pkg, _ = _parse_pkg_from_product_id(pid)
                        if flag_pkg and flag_pkg not in _resolve_comp(comp, ctx):
                            continue
                    lbl = _pid_label(pid, pid_name, rel_parent)
                    return pd.Series(["✅ FALSE POSITIVE", "N/A",
                        f"Not affected in {ctx.display_name} ({lbl}): "
                        f"{flag.get('label', 'flag').replace('_', ' ')}.",
                        severity])

        # 2. Product-status entries for our scope.
        our_sha = _extract_sha256(ctx.image_ref or "")
        is_image_component = '/' in comp

        # 2a. Image-level SHA PIDs (more specific than RPM-level PIDs).
        if is_image_component:
            result = _audit_nonrpm_image_sha(
                comp, found_v, data, ctx, pid_name, rel_parent,
                rhel_base_pids, vex_ns_map, severity, our_sha, row,
                pid_cpe=pid_cpe)
            if result is not None:
                return result

        # 2b. Generic product_status scan (non-SHA PIDs matched by name).
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for status in ('known_not_affected', 'known_affected', 'fixed',
                           'under_investigation'):
                for pid in ps.get(status, []):
                    if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                        continue
                    pid_sha = _extract_sha256(pid)
                    if pid_sha:
                        if not our_sha or pid_sha != our_sha:
                            continue
                    else:
                        pid_pkg, _ = _parse_pkg_from_product_id(pid)
                        if pid_pkg and pid_pkg not in _resolve_comp(comp, ctx):
                            continue
                    lbl = _pid_label(pid, pid_name, rel_parent)
                    if status == 'under_investigation':
                        return pd.Series(["❌ POSITIVE", "N/A",
                            f"under_investigation for {ctx.display_name}.",
                            severity])
                    if status == "known_not_affected":
                        result = "✅ FALSE POSITIVE"
                        note = f"known_not_affected ({lbl})."
                    elif status == "fixed":
                        result = "❌ POSITIVE"
                        note = f"Fix exists ({lbl}); installed version not verified."
                    else:
                        result = "❌ POSITIVE"
                        note = f"known_affected ({lbl})."
                    return pd.Series([result, "N/A", note, severity])

    # ── Fallthrough: no in-scope match found ────────────────────────────
    return _audit_nonrpm_fallthrough(
        comp, ctx, pid_name, rel_parent, rhel_base_pids, vex_ns_map,
        severity, affected, fixed, not_affected, investigating, data,
        pid_cpe=pid_cpe)


def _audit_nonrpm_image_sha(comp, found_v, data, ctx, pid_name, rel_parent,
                             rhel_base_pids, vex_ns_map, severity, our_sha, row,
                             pid_cpe: Optional[dict] = None):
    """Check image-level VEX PIDs with @sha256: digests.

    Returns pd.Series result or None if no conclusion reached.
    """
    comp_base = re.sub(r'[@:][^/]*$', '', comp)
    img_not_affected = False
    img_fixed_label = None
    img_fixed_ver = str(row.get('FIXED_VERSION', '')) if 'FIXED_VERSION' in row.index else None

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        for status in ('known_not_affected', 'fixed', 'known_affected',
                       'under_investigation'):
            for pid in ps.get(status, []):
                if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    continue
                pid_sha = _extract_sha256(pid)
                if not pid_sha:
                    continue
                pid_image = re.sub(
                    r'@sha256:[a-f0-9]+.*$', '',
                    pid.split(':', 1)[-1] if ':' in pid else pid)
                if pid_image != comp_base:
                    continue
                lbl = _pid_label(pid, pid_name, rel_parent)
                if status == 'known_not_affected':
                    if our_sha and pid_sha == our_sha:
                        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                            f"Image build not affected ({lbl}).", severity])
                    img_not_affected = True
                elif status == 'fixed':
                    if our_sha and pid_sha == our_sha:
                        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                            f"Image build is the fixed version ({lbl}).",
                            severity])
                    img_fixed_label = lbl
                elif status == 'known_affected':
                    if our_sha and pid_sha == our_sha:
                        fix_note = f"; fix: {img_fixed_ver}" if img_fixed_ver else ""
                        return pd.Series(["❌ POSITIVE", img_fixed_ver or "N/A",
                            f"Image build affected ({lbl}){fix_note}.",
                            severity])
                elif status == 'under_investigation':
                    if our_sha and pid_sha == our_sha:
                        return pd.Series(["❌ POSITIVE", "N/A",
                            f"under_investigation for {ctx.display_name}.",
                            severity])

    # A fixed image build exists but our digest doesn't match it.
    if img_fixed_label and not img_not_affected:
        fix_note = f" Fix: {img_fixed_ver}." if img_fixed_ver else ""
        return pd.Series(["❌ POSITIVE", img_fixed_ver or "N/A",
            f"Fixed build exists ({img_fixed_label}); installed {found_v} "
            f"is older.{fix_note}", severity])

    return None


def _audit_nonrpm_fallthrough(comp, ctx, pid_name, rel_parent, rhel_base_pids,
                               vex_ns_map, severity, affected, fixed,
                               not_affected, investigating, data,
                               pid_cpe: Optional[dict] = None):
    """Handle unscoped non-RPM fallthrough (UBI or no in-scope match).

    Returns pd.Series([verdict, fix, justification, severity]).
    """
    # Scope status labels to the workload context to avoid cross-contamination
    # from unrelated product families.  Verdict order within scope:
    # affected > under_investigation > clear (known_not_affected/fixed).
    # A product whose in-scope entries for this CVE are ALL clear was assessed
    # by Red Hat with nothing affected — the finding is a false positive even
    # when the component name itself never appears (e.g. a Go module tracked
    # at the RPM level under the same product).
    if ctx.workload_type != "ubi":
        scoped_affected = []
        scoped_investigating = []
        scoped_clear = []
        for vuln in data.get('vulnerabilities', []):
            ps = vuln.get('product_status', {})
            for pid in ps.get('known_affected', []):
                if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    scoped_affected.append(_pid_label(pid, pid_name, rel_parent))
            for pid in ps.get('under_investigation', []):
                if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                    scoped_investigating.append(_pid_label(pid, pid_name, rel_parent))
            for status in ('known_not_affected', 'fixed'):
                for pid in ps.get(status, []):
                    if _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                     pid_cpe=pid_cpe):
                        scoped_clear.append(_pid_label(pid, pid_name, rel_parent))
        if scoped_affected:
            unique_labels = sorted(set(scoped_affected))
            return pd.Series(["❌ POSITIVE", "N/A",
                f"known_affected in {', '.join(unique_labels[:3])}.", severity])
        if scoped_investigating:
            unique_labels = sorted(set(scoped_investigating))
            return pd.Series(["❌ POSITIVE", "N/A",
                f"under_investigation in {', '.join(unique_labels[:3])}.",
                severity])
        if scoped_clear:
            unique_labels = sorted(set(scoped_clear))
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                f"No affected entry in {', '.join(unique_labels[:3])} "
                f"(known_not_affected/fixed only).", severity])

    # Operator with no VEX assessment for this product family.
    if ctx.workload_type == "operator" and (affected or investigating or fixed):
        return pd.Series(["❌ POSITIVE", "N/A",
            f"No VEX assessment for {ctx.display_name}.", severity])

    if investigating:
        return pd.Series(["❌ POSITIVE", "N/A",
            f"under_investigation in {', '.join(investigating[:3])}.", severity])

    if not_affected and not affected and not fixed:
        return pd.Series(["✅ FALSE POSITIVE", "N/A",
            f"known_not_affected in {', '.join(not_affected[:3])}.", severity])

    # RHEL-version-specific check: our RHEL not affected but others are.
    if affected and not_affected and ctx.rhel_ver:
        rhel_tag = f"RHEL {ctx.rhel_ver}"
        rhel_tag_long = f"Red Hat Enterprise Linux {ctx.rhel_ver}"
        workload_rhel_clear = any(
            rhel_tag in na or rhel_tag_long in na for na in not_affected)
        workload_rhel_affected = any(
            rhel_tag in af or rhel_tag_long in af for af in affected)
        if workload_rhel_clear and not workload_rhel_affected:
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                f"RHEL {ctx.rhel_ver} not affected. Only affects: "
                f"{', '.join(affected[:2])}.", severity])

    parts = []
    if affected:     parts.append(f"affected: {', '.join(affected[:3])}")
    if fixed:        parts.append(f"fixed: {', '.join(fixed[:3])}")
    if not_affected: parts.append(f"not affected: {', '.join(not_affected[:3])}")
    return pd.Series(["❌ POSITIVE", "N/A",
        f"No VEX entry for {ctx.display_name}. Other products: "
        f"{'; '.join(parts)}.", severity])


def _compare_fixed_rpm(found_v, unique_fixed, comp, ctx, severity, rpm_rhel):
    """Stream-aware RPM version comparison against VEX fixed versions.

    Red Hat backports fixes to older EUS/E4S minor streams with lower upstream
    version numbers.  When the installed package carries a minor stream marker
    (el9_4), only compare against fixes from the same minor stream.

    Returns pd.Series([verdict, fix, justification, severity]).
    """
    installed_minor = _detect_rhel_minor(found_v)
    sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''

    if installed_minor:
        same_stream = [v for v in unique_fixed
                       if _detect_rhel_minor(v) == installed_minor]
        if same_stream:
            compare_fixes = same_stream
        else:
            # Fix in other streams but not this minor stream yet.
            best_ref = unique_fixed[0]
            prefix = f"{sn}; " if sn else ''
            return pd.Series(["❌ POSITIVE", best_ref,
                f"{prefix}No fix in el{ctx.rhel_ver}_{installed_minor}. "
                f"Fix in other streams: {best_ref}.", severity])
    else:
        compare_fixes = unique_fixed

    # GA packages (no minor stream marker) must be >= ALL stream fixes.
    all_pass = True
    any_compared = False
    any_fail_fix = None
    for fix_v in compare_fixes:
        try:
            cmp_inst, cmp_fix = _normalize_epoch(found_v, fix_v)
            any_compared = True
            if compare_versions(cmp_inst, cmp_fix) < 0:
                all_pass = False
                if any_fail_fix is None:
                    any_fail_fix = fix_v
        except Exception:
            pass

    if all_pass and compare_fixes and any_compared:
        note = f"{sn + '; ' if sn else ''}Installed {found_v} >= fix {compare_fixes[0]}."
        return pd.Series(["✅ FALSE POSITIVE", compare_fixes[0], note, severity])
    if any_fail_fix:
        note = f"{sn + '; ' if sn else ''}Installed {found_v} < fix {any_fail_fix}."
        return pd.Series(["❌ POSITIVE", any_fail_fix, note, severity])
    fix_ref = compare_fixes[0] if compare_fixes else "?"
    note = f"{sn + '; ' if sn else ''}Installed {found_v} < fix {fix_ref}."
    return pd.Series(["❌ POSITIVE",
                       compare_fixes[0] if compare_fixes else "N/A",
                       note, severity])


def _audit_rpm(comp, found_v, data, ctx, pid_name, rel_parent,
               rhel_base_pids, pid_purl, vex_ns_map, severity, pid_severity,
               rhel_ver, rpm_rhel, row,
               pid_cpe: Optional[dict] = None):
    """Audit an RPM component (version has .elN marker).

    Checks VEX product_status entries with RPM version comparison, respecting
    module-stream boundaries and minor-stream backport tracks.

    Returns pd.Series([verdict, fix, justification, severity]).
    """
    names_to_match = _resolve_comp(comp, ctx)
    # VEX-derived source aliases (ceph-mon → ceph) — see _src_alias_names.
    names_to_match |= _src_alias_names(data, comp, found_v)

    for vuln in data.get('vulnerabilities', []):
        ps = vuln.get('product_status', {})
        flags = vuln.get('flags', [])

        # ── Known-not-affected (product_status + not-affected flags) ────
        not_affected_ids = set(ps.get('known_not_affected', []))
        for flag in flags:
            if flag.get('label') in _NOT_AFFECTED_FLAGS:
                not_affected_ids.update(flag.get('product_ids', []))

        installed_minor = _detect_rhel_minor(found_v)
        for pid in not_affected_ids:
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, pkg_ver = _parse_pkg_from_product_id(pid)
            if pkg_name not in names_to_match:
                continue
            if pid in pid_severity:
                severity = pid_severity[pid]
            # Stream-aware KNA: a KNA from a different minor stream does not
            # apply — that stream's fix status may differ.
            if installed_minor and pkg_ver:
                kna_minor = _detect_rhel_minor(pkg_ver)
                if kna_minor and kna_minor != installed_minor:
                    continue
            sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''
            prefix = f"{sn}; " if sn else ''
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                f"{prefix}{ctx.display_name}: known_not_affected.", severity])

        # ── Fixed versions in scope ─────────────────────────────────────
        # Collect (version, from_rhel_base) so RHEL base-repo fixes are
        # preferred as the reported reference over add-on product builds
        # (e.g. AppStream 1.26.19-3.el9_8 beats Ansible's 2.7.0-1.el9ap).
        scoped_fixed = []
        for pid in ps.get('fixed', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, pkg_ver = _parse_pkg_from_product_id(pid)
            if pkg_name in names_to_match and pkg_ver:
                if pid in pid_severity:
                    severity = pid_severity[pid]
                is_base = pid.split(':')[0] in rhel_base_pids
                scoped_fixed.append((pkg_ver, is_base))

        if scoped_fixed:
            scoped_fixed.sort(key=lambda t: not t[1])   # base repos first
            seen, unique_fixed = set(), []
            for v, _b in scoped_fixed:
                if v not in seen:
                    seen.add(v)
                    unique_fixed.append(v)
            return _compare_fixed_rpm(
                found_v, unique_fixed, comp, ctx, severity, rpm_rhel)

        # ── Known-affected in scope ─────────────────────────────────────
        no_fix_pids = set()
        for remed in vuln.get('remediations', []):
            if remed.get('category') == 'no_fix_planned':
                no_fix_pids.update(remed.get('product_ids', []))

        for pid in ps.get('known_affected', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in names_to_match:
                if pid in pid_severity:
                    severity = pid_severity[pid]
                other_products = set()
                for fpid in ps.get('fixed', []):
                    if (_is_any_rhel_ver_product(fpid, rhel_ver)
                            and not _pid_in_scope(fpid, ctx, pid_name,
                                                  rhel_base_pids, vex_ns_map,
                                                  pid_cpe=pid_cpe)):
                        fpkg, _ = _parse_pkg_from_product_id(fpid)
                        if fpkg and fpkg in names_to_match:
                            other_products.add(
                                _pid_label(fpid, pid_name, rel_parent))
                sn = _sbom_note(comp, found_v, ctx) if rpm_rhel else ''
                prefix = f"{sn}; " if sn else ''
                if pid in no_fix_pids:
                    note = f"{prefix}known_affected. no_fix_planned."
                elif other_products:
                    ctx_str = ", ".join(sorted(other_products))
                    note = f"{prefix}known_affected. Fix only in: {ctx_str}."
                else:
                    note = f"{prefix}known_affected. No fix available."
                return pd.Series(["❌ POSITIVE", "N/A", note, severity])

        # ── Under-investigation in scope ────────────────────────────────
        for pid in ps.get('under_investigation', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                continue
            pkg_name, _ = _parse_pkg_from_product_id(pid)
            if pkg_name in names_to_match:
                return pd.Series(["❌ POSITIVE", "N/A",
                    f"under_investigation for {ctx.display_name}.", severity])

        # ── Cross-product fallback ──────────────────────────────────────
        # Related-product evidence: PIDs matching the workload's RHEL version
        # OR version-neutral product PIDs (no el/rhel marker — e.g.
        # red_hat_openshift_container_platform_4:openshift-clients), which
        # cannot contradict the workload's RHEL version.
        other_vuln, other_safe = set(), set()
        for status in ('fixed', 'known_affected', 'known_not_affected'):
            for pid in ps.get(status, []):
                if ((_is_any_rhel_ver_product(pid, rhel_ver)
                        or _is_version_neutral_product(pid))
                        and not _pid_in_scope(pid, ctx, pid_name,
                                              rhel_base_pids, vex_ns_map,
                                              pid_cpe=pid_cpe)):
                    if _pid_module_stream(pid) and not _version_is_module_stream(found_v):
                        continue
                    pkg_name, _ = _parse_pkg_from_product_id(pid)
                    if pkg_name in names_to_match:
                        label = _pid_label(pid, pid_name, rel_parent)
                        if status in ('known_affected', 'fixed'):
                            other_vuln.add(label)
                        else:
                            other_safe.add(label)

        if other_safe and not other_vuln:
            ctx_str = ", ".join(sorted(other_safe))
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                f"'{comp}' not affected in related products ({ctx_str}).",
                severity])
        if other_vuln:
            ctx_str = ", ".join(sorted(other_vuln))
            return pd.Series(["❌ POSITIVE", "N/A",
                f"'{comp}' affected in related products ({ctx_str}).",
                severity])

        return pd.Series(["⚠️ NOT ASSESSED", "N/A",
            f"'{comp}' not tracked in VEX.", severity])

    return pd.Series(["❌ POSITIVE", "N/A",
                       "No vulnerability entries in VEX.", severity])


def _derive_state(verdict: str, fix: str, justification: str, data,
                  ctx: WorkloadContext, comp: str) -> str:
    """Derive the Red Hat page State (Will not fix / Fix deferred / Affected /
    Not affected / Fixed / Fix available / Under investigation) for the finding.

    Data-driven from VEX remediations: `no_fix_planned` and `none_available`
    entries carry the display text in their `details` field.
    """
    if data is None or 'VEX file missing' in justification:
        return 'Unknown'

    if 'NOT ASSESSED' in verdict:
        return 'Not assessed'

    if 'FALSE' in verdict:
        j = justification
        if '>= fix' in j or 'Fixed in' in j or 'fixed build' in j or 'backported' in j:
            return 'Fixed'
        return 'Not affected'

    # POSITIVE
    if 'under_investigation' in justification:
        return 'Under investigation'
    if fix and fix not in ('N/A', '', 'nan', '-'):
        return 'Fix available'

    # Look up remediation state for the in-scope affected PIDs.
    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe = _build_pid_name(data)
    rem_map = data.get('__rem_map__')
    if rem_map is None:
        rem_map = {}
        for vuln in data.get('vulnerabilities', []):
            for rem in vuln.get('remediations', []):
                cat = rem.get('category', '')
                det = (rem.get('details') or '').strip()
                for pid in rem.get('product_ids', []):
                    rem_map.setdefault(pid, []).append((cat, det))
        data['__rem_map__'] = rem_map

    no_fix_det, none_avail_det = None, None
    for vuln in data.get('vulnerabilities', []):
        for pid in vuln.get('product_status', {}).get('known_affected', []):
            if not _pid_in_scope(pid, ctx, pid_name, rhel_base_pids, vex_ns_map,
                                 pid_cpe=pid_cpe):
                continue
            for cat, det in rem_map.get(pid, []):
                if cat == 'no_fix_planned' and no_fix_det is None:
                    no_fix_det = det or 'Will not fix'
                elif cat == 'none_available' and none_avail_det is None:
                    none_avail_det = det or 'Affected'
    if no_fix_det:
        return no_fix_det
    if none_avail_det:
        return 'Fix deferred' if 'defer' in none_avail_det.lower() else none_avail_det
    return 'Affected'


def audit_row_detailed(row, ctx: WorkloadContext):
    """Triage a single CVE row against the Red Hat VEX database.

    Returns pd.Series([verdict, fix_version, justification, severity, state])
    where state is Red Hat's remediation state (Will not fix, Fix deferred,
    Affected, Not affected, Fixed, Fix available, Under investigation).
    """
    res = _audit_verdict(row, ctx)
    cve = row['CVE'].strip().upper()
    state = _derive_state(res.iloc[0], str(res.iloc[1]), str(res.iloc[2]),
                          _load_vex(cve), ctx, row['COMPONENT'])
    return pd.Series([res.iloc[0], res.iloc[1], res.iloc[2], res.iloc[3], state])


def _audit_verdict(row, ctx: WorkloadContext):
    """Core verdict engine — returns pd.Series([verdict, fix, justification, severity])."""
    comp    = row['COMPONENT']
    found_v = str(row['VERSION'])
    cve     = row['CVE'].strip().upper()

    # ── Load VEX data and build lookup maps ─────────────────────────────
    data = _load_vex(cve)
    if data is None:
        return pd.Series(["❌ POSITIVE", "N/A", "VEX file missing.", "Unknown"])

    pid_name, rel_parent, rhel_base_pids, pid_purl, vex_ns_map, pid_cpe = _build_pid_name(data)
    pid_severity = _build_pid_severity_map(data)

    # ── Resolve severity (baseline — RPM branch may override per-PID) ───
    severity = _resolve_base_severity(
        data, comp, ctx, pid_name, rhel_base_pids, vex_ns_map,
        pid_severity, row, pid_cpe=pid_cpe, pid_purl=pid_purl)

    # ── Catch-all: vendor-level "no Red Hat product affected" ───────────
    if _is_catchall_not_affected(data):
        return pd.Series(["✅ FALSE POSITIVE", "N/A",
                           "No supported Red Hat product affected.", severity])

    # ── Build-level override: our exact image digest assessed in VEX ────
    # A digest is globally unique; a VEX statement about it describes THIS
    # build and overrides stream-level entries for every component in it
    # (RPM and non-RPM alike).
    img_sha = _extract_sha256(ctx.image_ref or '')
    if img_sha:
        sha_hits = {}
        for vuln in data.get('vulnerabilities', []):
            ps_ = vuln.get('product_status', {})
            for status in ('known_affected', 'under_investigation',
                           'fixed', 'known_not_affected'):
                for pid in ps_.get(status, []):
                    if img_sha in pid:
                        sha_hits.setdefault(status, pid)
        if sha_hits:
            if 'known_affected' in sha_hits or 'under_investigation' in sha_hits:
                st = ('known_affected' if 'known_affected' in sha_hits
                      else 'under_investigation')
            else:
                st = ('known_not_affected' if 'known_not_affected' in sha_hits
                      else 'fixed')
            decisive = sha_hits[st]
            if decisive in pid_severity:
                severity = pid_severity[decisive]
            lbl = _pid_label(decisive, pid_name, rel_parent)
            if st in ('known_affected', 'under_investigation'):
                return pd.Series(["❌ POSITIVE", "N/A",
                    f"{st} — this image build ({lbl}).", severity])
            note = ("This image build is the fixed build"
                    if st == 'fixed' else "known_not_affected — this image build")
            return pd.Series(["✅ FALSE POSITIVE", "N/A",
                f"{note} ({lbl}).", severity])

    # ── Determine effective RHEL version from RPM version string ────────
    # The RPM's own .elN marker is authoritative — mixed-RHEL images
    # need per-row scoping.  Components with '/' are image refs (RHACS
    # image-identity pseudo-components carry SOURCE=OS and sometimes
    # elN-looking versions) — they always take the non-RPM path.
    if '/' in comp:
        rpm_rhel = None
    else:
        rpm_rhel = _detect_rhel_ver(found_v)

        # SOURCE-based classification: RHACS scan components carry a SOURCE
        # field (OS, GO, JAVA, NPM, PYTHON, etc.).  SOURCE=OS means the
        # component is an OS/RPM package even when the version string lacks
        # the usual .elN marker.
        comp_source = str(row.get('SOURCE', '')) if 'SOURCE' in row.index else ''
        if not rpm_rhel and comp_source == 'OS':
            rpm_rhel = ctx.rhel_ver

    rhel_ver = rpm_rhel or ctx.rhel_ver
    if rpm_rhel and rpm_rhel != ctx.rhel_ver:
        ctx = WorkloadContext(
            **{f.name: getattr(ctx, f.name)
               for f in ctx.__dataclass_fields__.values()})
        ctx.rhel_ver = rpm_rhel

    # ── Branch: non-RPM (Go, npm, image ref) vs RPM ────────────────────
    if not rpm_rhel:
        return _audit_nonrpm(
            comp, found_v, data, ctx, pid_name, rel_parent,
            rhel_base_pids, pid_purl, vex_ns_map, severity, row,
            pid_cpe=pid_cpe)

    return _audit_rpm(
        comp, found_v, data, ctx, pid_name, rel_parent,
        rhel_base_pids, pid_purl, vex_ns_map, severity, pid_severity,
        rhel_ver, rpm_rhel, row, pid_cpe=pid_cpe)


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
    "❌ POSITIVE":       "bold red",
    "⚠️ NOT ASSESSED":  "bold yellow",
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
            'AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'VEX_STATE',
            'RHACS_SEVERITY', 'SEVERITY_MISMATCH']
    # Include RHACS metadata columns when present
    for extra in ('SOURCE', 'LOCATION', 'FIXED_VERSION', 'OCP_COMPONENT', 'IMAGE', 'IMAGE_ROLE'):
        if extra in df.columns:
            cols.append(extra)
    # Ensure all expected columns exist even on an empty DataFrame
    for col in cols:
        if col not in df.columns:
            df[col] = pd.Series(dtype=str)

    result_df = df[cols].copy()

    # Add FIXABLE column: True if either VEX or RHACS reports a fix version
    vex_fix = result_df['VEX_FIX_VER'].fillna('').astype(str).str.strip()
    rhacs_fix = result_df['FIXED_VERSION'].fillna('').astype(str).str.strip() if 'FIXED_VERSION' in result_df.columns else pd.Series('', index=result_df.index)
    result_df['FIXABLE'] = ((vex_fix != '') & (vex_fix != 'N/A') & (vex_fix != 'nan')) | \
                           ((rhacs_fix != '') & (rhacs_fix != 'nan'))
    if result_df.empty:
        if false_only:
            result_df = result_df[result_df['AUDIT_RESULT'] == '✅ FALSE POSITIVE']
        return result_df

    def _sort_key(row):
        j, r = row['JUSTIFICATION'], row['AUDIT_RESULT']
        if '✅' in r:                                            priority = 0
        elif '⚠️' in r:                                          priority = 1
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


def _short_component(comp: str) -> str:
    """Shorten module paths for display using structural rules only.

    A first path segment containing a dot is a hostname — drop it. From the
    remainder, keep the last segment, or the last two when the final one is a
    bare major-version suffix (v5): github.com/go-git/go-git/v5 → go-git/v5.
    """
    if '/' not in comp:
        return comp
    parts = comp.split('/')
    if '.' in parts[0]:
        parts = parts[1:]
    if not parts:
        return comp
    if len(parts) >= 2 and re.fullmatch(r'v\d+', parts[-1]):
        return '/'.join(parts[-2:])
    return parts[-1]


def _render_triage_table(console: Console, result_df: pd.DataFrame, ctx) -> None:
    """Render a compact box table: POSITIVE first, one line per finding,
    RHACS vs VEX severity side by side, summary footer.

    The box is drawn manually with fixed computed widths so the layout never
    collapses when the terminal is narrow or output is piped.
    """
    _vstyle = {'POSITIVE': 'bold red', 'FALSE POSITIVE': 'bold green',
               'NOT ASSESSED': 'bold yellow'}
    _sev_rank = {'Critical': 0, 'Important': 1, 'Moderate': 2, 'Low': 3, 'Unknown': 4}

    rows = []
    for _, row in result_df.iterrows():
        verdict = str(row['AUDIT_RESULT'])
        verdict_plain = ('FALSE POSITIVE' if 'FALSE' in verdict
                         else 'NOT ASSESSED' if 'NOT ASSESSED' in verdict
                         else 'POSITIVE')
        fix = str(row.get('VEX_FIX_VER', '') or '')
        rows.append({
            'cve': str(row['CVE']),
            'comp': _short_component(str(row['COMPONENT'])),
            'rhacs': str(row.get('RHACS_SEVERITY', 'Unknown')),
            'vex': str(row.get('SEVERITY', 'Unknown')),
            'verdict': verdict_plain,
            'state': str(row.get('VEX_STATE', '') or '-'),
            'fix': fix if fix not in ('', 'N/A', 'nan') else '-',
            'just': str(row['JUSTIFICATION']),
        })
    rows.sort(key=lambda r: (
        0 if r['verdict'] == 'POSITIVE' else 1 if r['verdict'] == 'NOT ASSESSED' else 2,
        _sev_rank.get(r['vex'], 9),
        _sev_rank.get(r['rhacs'], 9),
        r['cve'],
    ))

    # Fixed-layout box: width = min(longest content, cap), never terminal-fitted.
    columns = [
        ('CVE',           'cve',     18),
        ('Component',     'comp',    26),
        ('RHACS Sev',     'rhacs',   10),
        ('VEX Sev',       'vex',     10),
        ('Verdict',       'verdict', 14),
        ('State',         'state',   20),
        ('Fix',           'fix',     18),
        ('Justification', 'just',    46),
    ]
    widths = [max(len(h), min(max((len(r[k]) for r in rows), default=0), cap))
              for h, k, cap in columns]

    def cell(text, w):
        return (text[:w - 1] + '…') if len(text) > w else text.ljust(w)

    def style_for(key, r):
        if key in ('rhacs', 'vex'):
            return SEVERITY_STYLES.get(r[key], 'dim')
        if key == 'verdict':
            return _vstyle[r['verdict']]
        if key == 'comp':
            return 'cyan'
        if key == 'fix':
            return 'dim'
        return ''

    top = '┌─' + '─┬─'.join('─' * w for w in widths) + '─┐'
    mid = '├─' + '─┼─'.join('─' * w for w in widths) + '─┤'
    bot = '└─' + '─┴─'.join('─' * w for w in widths) + '─┘'

    console.print(top, markup=False, soft_wrap=True)
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

    # ── Summary footer ───────────────────────────────────────────────────
    total = len(rows)
    if not total:
        return
    fp  = sum(1 for r in rows if r['verdict'] == 'FALSE POSITIVE')
    pos = sum(1 for r in rows if r['verdict'] == 'POSITIVE')
    na  = sum(1 for r in rows if r['verdict'] == 'NOT ASSESSED')

    rhacs_counts = Counter(r['rhacs'] for r in rows)
    rhacs_str = ", ".join(f"{n} {s}" for s, n in
                          sorted(rhacs_counts.items(), key=lambda kv: _sev_rank.get(kv[0], 9)))
    sev_shift = sum(1 for r in rows if r['rhacs'] not in ('Unknown', r['vex']))

    label = ctx.image_ref or ctx.display_name
    m = re.search(r'@sha256:([a-f0-9]{6})', label or '')
    if m:
        label = re.sub(r'@sha256:[a-f0-9]+', f" (sha256:{m.group(1)}...)", label)
    console.print(f"\nImage: [bold cyan]{label}[/bold cyan]")
    na_str = f", {na} not assessed" if na else ""
    console.print(
        f"RHACS reports [bold]{total}[/bold] findings ({rhacs_str}) → VEX triage: "
        f"[bold green]{fp} false positives[/bold green] ({100 * fp // total}%), "
        f"[bold red]{pos} real[/bold red]{na_str}."
    )
    if sev_shift:
        console.print(f"[yellow]{sev_shift} finding(s) rated differently by Red Hat VEX than by the scanner.[/yellow]")
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
        for col in ['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE',
                    'VEX_PRODUCT', 'RHACS_SEVERITY', 'SEVERITY_MISMATCH']:
            df[col] = pd.Series(dtype=str)
    else:
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE']] = df.apply(
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
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE']] = df.apply(
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
            try:
                image_data = rhacs_scan_image(session, image_ref, force=force)
            except TypeError:
                # Corrupted requests_cache entry — purge and retry without cache
                session.cache.delete(expired=True)
                image_data = rhacs_scan_image(session, image_ref, force=True)
            if not image_data:
                return {"found": False, "error": None}
        else:
            try:
                image_data = rhacs_get_image(session, image_id, force=force, image_ref=image_ref)
            except TypeError:
                session.cache.delete(expired=True)
                image_data = rhacs_get_image(session, image_id, force=True, image_ref=image_ref)
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
            if comp_name:
                img_ctx.ocp_component = comp_name

        # Build binary→source RPM name map from SBOM GENERATED_FROM relationships.
        # Uses lib4sbom to parse the SPDX 2.3 SBOM rather than walking raw dicts.
        try:
            _sbom = rhacs_get_sbom(session, image_ref, force=force)
            img_ctx.sbom_src_map = _build_sbom_src_map(_sbom)
            img_ctx.sbom_packages = _build_sbom_packages(_sbom)
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
    except Exception as e:
        return {"found": None, "error": f"{type(e).__name__}: {e}"}


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

    if args.ocp is not None and not use_ocp:
        _console.print("[red]Error:[/red] --ocp requires ROX_ENDPOINT and ROX_API_TOKEN environment variables.")
        raise SystemExit(1)
    if args.namespace is not None and not use_namespace:
        _console.print("[red]Error:[/red] --namespace requires ROX_ENDPOINT and ROX_API_TOKEN environment variables.")
        raise SystemExit(1)

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

            _force = getattr(args, 'force', False)

            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                future_to_comp = {
                    ex.submit(_fetch_and_audit, session, image_ref, None,
                              args.false_only, _manifest_ocp_ver,
                              _force, comp_name):
                        (comp_name, image_ref)
                    for comp_name, image_ref in images
                }
                done = 0
                for future in as_completed(future_to_comp):
                    done += 1
                    comp_name, image_ref = future_to_comp[future]
                    res = future.result()
                    results_map[comp_name] = (image_ref, res)
                    status = "✅" if res.get("found") \
                             else ("⚠ " if res.get("found") is False else "❌")
                    suffix = ""
                    if res.get("found") is False:
                        suffix = f"  [dim]{image_ref}[/dim]"
                    elif res.get("found") is None and res.get("error"):
                        suffix = f"  [red]{res['error'][:80]}[/red]"
                    _console.print(f"  [{done}/{total}] {status} {comp_name}{suffix}", highlight=False)

            # Retry any images that failed due to API errors (found=None).
            failed = [(cn, ir) for cn, ir in images
                      if results_map.get(cn, (None, {}))[1].get("found") is None]
            if failed:
                _console.print(f"\n[yellow]⚠  {len(failed)} image(s) failed — retrying...[/yellow]")
                time.sleep(5)
                with ThreadPoolExecutor(max_workers=args.workers) as ex:
                    retry_futures = {
                        ex.submit(_fetch_and_audit, session, ir, None,
                                  args.false_only, _manifest_ocp_ver, True, cn):
                            (cn, ir) for cn, ir in failed
                    }
                    for future in as_completed(retry_futures):
                        cn, ir = retry_futures[future]
                        res = future.result()
                        results_map[cn] = (ir, res)
                        status = "✅" if res.get("found") \
                                 else ("⚠ " if res.get("found") is False else "❌")
                        _console.print(f"  [retry] {status} {cn}", highlight=False)

            _console.print()

            # Display results in original manifest order
            all_results: list = []
            for comp_name, image_ref in images:
                image_ref_stored, res = results_map.get(comp_name, (image_ref, {"found": False, "error": None}))
                _display_image_result(_console, f"{comp_name}  [dim]{image_ref_stored}[/dim]", res)
                if res.get("found") is False:
                    not_found.append(comp_name)
                elif res.get("result_df") is not None:
                    r = res["result_df"].copy()
                    r["OCP_COMPONENT"] = comp_name
                    r["IMAGE"]         = image_ref_stored
                    all_results.append(r)

            # Collect images that still failed after retry
            still_failed = [(cn, ir) for cn, ir in images
                            if results_map.get(cn, (None, {}))[1].get("found") is None]

            _console.rule("[bold]OCP Release Summary[/bold]")
            _console.print(f"  Scanned : [bold]{total - len(not_found) - len(still_failed)}[/bold] / {total} component image(s)")
            if not_found:
                _console.print(f"  Skipped : [yellow]{len(not_found)}[/yellow] not found in RHACS")
            if still_failed:
                _console.print(f"  Failed  : [red]{len(still_failed)}[/red] errored after retry:")
                for cn, ir in still_failed:
                    err = results_map.get(cn, (None, {}))[1].get("error", "unknown")
                    _console.print(f"    [red]•[/red] {cn}: {err[:120]}")
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

            # Exit with non-zero if images failed — signals to setup_and_scan
            # that the report is incomplete and should be re-run.
            if still_failed:
                _console.print(f"[yellow]⚠  Exiting with code 2 — {len(still_failed)} image(s) still failed.[/yellow]")
                raise SystemExit(2)
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
                ctx.sbom_packages = _build_sbom_packages(_sbom)
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
