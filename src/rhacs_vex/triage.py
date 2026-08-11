"""triage.py — RHACS↔Red Hat VEX triage CLI and IO layer.

The matching engine lives in `rhacs_vex.engine`; this module is IO and
presentation only:  the Red Hat VEX mirror (ETag-cached download), the RHACS API
client (scan / image / SBOM fetch + local caches), DataFrame flattening, SBOM
cross-check, the rich table renderer, and the CLI (`--scan`, `--image`,
`--namespace`, `--ocp`, `--sbom`, `--show-scan`).

The engine's public API is re-exported here so sibling modules
(rhacs_vex.operators, rhacs_vex.retriage, rhacs_vex.parquet, and the
tests/check_baseline.py harness) keep referencing `triage.<symbol>`.
"""

import argparse
import os
import re
import json
import threading
import time
import tempfile
import requests
import requests_cache
from datetime import timedelta
import pandas as pd
from collections import Counter
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from lib4sbom.parser import SBOMParser as _SBOMParser
from rich.console import Console
from rich.table import Table
from rich import box

# ── Engine (re-exported so sibling modules keep `triage.<symbol>` working) ──
from .engine import (  # noqa: F401
    WorkloadContext, parse_image_ref, parse_context_from_labels,
    audit_row_detailed, _vex_product_for_row, _get_vex_product,
    _load_vex, _RHACS_SEVERITY_MAP, compare_versions, _normalize_epoch,
    BASE_DIR, VEX_DIR, wire_rpm_owners, rpm_file_owners_from_sbom,
    rpm_source_map_from_sbom,
)

# --- 1. JUPYTER VIEW CONFIGURATION ---
pd.set_option('display.max_colwidth', None)
pd.set_option('display.max_rows', None)

# --- 2. CONFIGURATION & DIRECTORY SETUP ---
SBOM_DIR    = os.path.join(BASE_DIR, "sbom")
SCAN_DIR    = os.path.join(BASE_DIR, "scans")

SCAN_FILE       = "scan.csv"
SCAN_CACHE_TTL  = 4 * 3600   # seconds; HTTP-level re-fetch after 4 hours
LOCAL_CACHE_TTL = 24 * 3600  # seconds; re-use local JSON/SBOM files for 24 hours
MAX_WORKERS     = 20

# Create the folder structure
os.makedirs(VEX_DIR, exist_ok=True)

# --- 3. SYNC ENGINE: plain-file mirror with ETag revalidation ---
#
# The engine reads plain data/vex/CVE-*.json files; freshness is a file mtime
# TTL plus a conditional GET (If-None-Match → 304) once the TTL lapses.  The
# ETags live in one small sidecar — no blob store duplicating every response
# (the previous requests-cache sqlite grew to GBs and its entries, lacking
# server Cache-Control, never expired: verdicts froze at first fetch).

_VEX_TTL       = 4 * 3600            # revalidate at most every 4h — VEX updates daily
_VEX_META_PATH = os.path.join(VEX_DIR, '.etags.json')
_VEX_META_LOCK = threading.Lock()
try:
    with open(_VEX_META_PATH) as _fh:
        _VEX_META = json.load(_fh)
except Exception:
    _VEX_META = {}


def _vex_meta_set(cve_id: str, etag: str) -> None:
    with _VEX_META_LOCK:
        _VEX_META[cve_id] = etag
        fd, tmp = tempfile.mkstemp(dir=VEX_DIR, suffix='.tmp')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(_VEX_META, f)
            os.replace(tmp, _VEX_META_PATH)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def download_and_convert_with_lib(cve_id: str) -> tuple:
    """Mirror one Red Hat VEX JSON file, revalidating by ETag after the TTL.

    Within _VEX_TTL of the last check: no network at all.  After it: one
    conditional GET — 304 refreshes the TTL window, 200 rewrites the file.
    Network failure falls back to whatever is on disk (stale-if-error).
    """
    cve_id = cve_id.upper().strip()
    m = re.search(r'CVE-(\d{4})-', cve_id)
    if not m:
        return cve_id, False

    year      = m.group(1)
    url       = f"https://security.access.redhat.com/data/csaf/v2/vex/{year}/{cve_id.lower()}.json"
    json_path = os.path.join(VEX_DIR, f"{cve_id}.json")

    try:
        if time.time() - os.path.getmtime(json_path) < _VEX_TTL:
            return cve_id, True
    except OSError:
        pass

    headers = {}
    if os.path.exists(json_path):
        with _VEX_META_LOCK:
            etag = _VEX_META.get(cve_id, '')
        if etag:
            headers['If-None-Match'] = etag
    try:
        res = requests.get(url, timeout=10, headers=headers)
        if res.status_code == 304:
            os.utime(json_path, None)          # content unchanged — reset TTL
            return cve_id, True
        if res.status_code == 200:
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
            if res.headers.get('ETag'):
                _vex_meta_set(cve_id, res.headers['ETag'])
            return cve_id, True
        return cve_id, os.path.exists(json_path)
    except requests.RequestException:
        return cve_id, os.path.exists(json_path)


# --- 4. RHACS API CLIENT ---


def _rhacs_session(endpoint: str, token: str) -> requests_cache.CachedSession:
    """Build a CachedSession pre-configured for the RHACS API.

    Image detail / scan / SBOM responses are cached with per-endpoint TTLs;
    search + list endpoints are excluded so cluster state is always fresh.
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
    """Search RHACS for an image by reference and return its internal ID.

    Tries progressively shorter name forms if the full ref isn't found,
    including a cross-registry fallback using 'Image Remote:'.
    """
    bare = re.sub(r'[@:][^/]*$', '', image_ref)

    has_tag_or_digest = bool(re.search(r'[@:]', image_ref.split('/')[-1]))
    tag_suffix = None
    if has_tag_or_digest:
        m = re.search(r'(:[^/@]+)$', image_ref)
        if m:
            tag_suffix = m.group(1)

    bare_parts = bare.split('/', 1)
    bare_no_reg = bare_parts[1] if len(bare_parts) > 1 and '.' in bare_parts[0] else bare

    queries = [f'Image:{image_ref}', f'Image:{bare}']
    cross_reg_query = f'Image Remote:{bare_no_reg}'
    if bare_no_reg != bare:
        queries.append(cross_reg_query)

    all_avail: list = []

    for query in queries:
        is_fallback = query != f'Image:{image_ref}'
        url = f"{session.base_url}/v1/images"
        resp = session.get(url, params={"query": query, "pagination.limit": 20}, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("images", [])
        if not results:
            continue

        def _full_name(img: dict) -> str:
            n = img.get("name", "")
            return n if isinstance(n, str) else (n.get("fullName", "") if n else "")

        digest = re.search(r'@(sha256:[a-f0-9]+)', image_ref)
        if digest:
            for img in results:
                if digest.group(1) in json.dumps(img):
                    return img["id"]
            continue

        if not has_tag_or_digest:
            for img in results:
                if _full_name(img).endswith(":latest"):
                    return img["id"]
            for img in results:
                fn = _full_name(img) or img.get("id", "?")
                if fn not in all_avail:
                    all_avail.append(fn)
            continue

        if is_fallback and tag_suffix:
            for img in results:
                if _full_name(img).endswith(tag_suffix):
                    return img["id"]
            for img in results:
                fn = _full_name(img) or img.get("id", "?")
                if fn not in all_avail:
                    all_avail.append(fn)
            continue

        return results[0]["id"]

    if not has_tag_or_digest and all_avail:
        url = f"{session.base_url}/v1/images"
        resp = session.get(url, params={"query": f"Image:{all_avail[0]}", "pagination.limit": 1}, timeout=30)
        resp.raise_for_status()
        results = resp.json().get("images", [])
        if results:
            return results[0]["id"]

    if has_tag_or_digest:
        img_data = rhacs_scan_image(session, image_ref)
        if img_data:
            return img_data.get("id")

    return None


def rhacs_scan_image(session, image_ref: str, force: bool = False,
                     retries: int = 3, retry_delay: float = 10.0) -> Optional[dict]:
    """Fetch (or trigger) a scan for an image via POST /v1/images/scan.

    A JSON copy is saved to data/scans/ and reused within LOCAL_CACHE_TTL (24 h).
    Pass force=True to bypass all caches and re-scan from scratch.
    """
    os.makedirs(SCAN_DIR, exist_ok=True)

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
    for attempt in range(1, retries + 2):
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
        except (requests.Timeout, requests.ConnectionError):
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
    """Local path for a saved scan: data/scans/<sanitised_ref_or_id>.json"""
    name = image_ref if image_ref else image_id
    safe = re.sub(r'[^\w@:.+-]', '_', name)
    return os.path.join(SCAN_DIR, f"{safe}.json")


def _local_cache_fresh(path: str, image_ref: str = "") -> bool:
    """True when the cached copy at *path* is still usable.

    Digest-pinned references (@sha256:) are content-addressed and valid forever;
    tag/floating references keep the LOCAL_CACHE_TTL window.
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
    """Fetch full image detail (scan + metadata) from RHACS, cached 24 h."""
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
    for attempt in range(1, retries + 2):
        try:
            resp = session.get(url, params={"stripDescription": True}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            fd, tmp = tempfile.mkstemp(dir=SCAN_DIR, suffix='.tmp')
            with os.fdopen(fd, 'w') as fh:
                json.dump(data, fh, indent=2)
            os.replace(tmp, cache_path)
            return data
        except (requests.Timeout, requests.ConnectionError):
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
    """Local cache path for an image's SBOM: data/sbom/<name+sha>.sbom"""
    safe = re.sub(r'[^\w@:.+-]', '_', image_ref)
    return os.path.join(SBOM_DIR, f"{safe}.sbom")


def rhacs_get_sbom(session, image_ref: str, force: bool = False) -> dict:
    """Fetch SPDX 2.3 SBOM from RHACS, cached 24 h."""
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
    """Binary→source RPM name map from an SPDX SBOM (GENERATED_FROM rels).

    Feeds WorkloadContext.sbom_src_map, which the engine uses for binary→source
    aliasing (e.g. {"python3-urllib3": "python-urllib3", ...}).
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
    """{name → set(versions)} from an SPDX SBOM for per-row version verification."""
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


def sbom_to_packages_df(sbom: dict) -> pd.DataFrame:
    """Flatten SPDX 2.3 packages into a DataFrame (name/version/purpose/file)."""
    try:
        parser = _SBOMParser(sbom_type="spdx")
        parser.parse_string(json.dumps(sbom))
        rows = [
            {"NAME": pkg.get("name", ""), "VERSION": pkg.get("version", ""),
             "PURPOSE": pkg.get("type", ""), "FILE": pkg.get("filename", "")}
            for pkg in parser.get_packages() if pkg.get("name")
        ]
    except Exception:
        rows = [
            {"NAME": pkg.get("name", ""), "VERSION": pkg.get("versionInfo", ""),
             "PURPOSE": pkg.get("primaryPackagePurpose", ""), "FILE": pkg.get("packageFileName", "")}
            for pkg in sbom.get("packages", []) if pkg.get("name")
        ]
    return pd.DataFrame(rows, columns=["NAME", "VERSION", "PURPOSE", "FILE"])


def _verify_sbom_against_df(session, image_ref: str, result_df: pd.DataFrame) -> dict:
    """Cross-check every unique component+version in result_df against the SBOM."""
    try:
        sbom = rhacs_get_sbom(session, image_ref)
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
    """(full_image_name, rhacs_image_id) for every unique image in *namespace*."""
    url  = f"{session.base_url}/v1/images"
    resp = session.get(url, params={"query": f"Namespace:{namespace}", "pagination.limit": 1000},
                       timeout=30)
    resp.raise_for_status()
    seen: dict = {}
    for img in resp.json().get("images", []):
        name_val  = img.get("name", "")
        full_name = name_val if isinstance(name_val, str) else name_val.get("fullName", "")
        img_id    = img.get("id", "")
        if full_name and img_id and full_name not in seen:
            seen[full_name] = img_id
    return list(seen.items())


def rhacs_to_df(image_data: dict) -> pd.DataFrame:
    """Flatten an RHACS image scan response into the triage DataFrame shape."""
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


# --- 5. DISPLAY HELPERS ---

_SEVERITY_ORDER = {"Critical": 0, "Important": 1, "Moderate": 2, "Low": 3, "Unknown": 4}

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


def _sort_and_filter_df(df: pd.DataFrame, false_only: bool = False) -> pd.DataFrame:
    """Sort audit results by priority/severity, filter to false-positives if asked."""
    cols = ['COMPONENT', 'VEX_PRODUCT', 'VERSION', 'CVE', 'SEVERITY',
            'AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'VEX_STATE',
            'RHACS_SEVERITY', 'SEVERITY_MISMATCH']
    for extra in ('SOURCE', 'LOCATION', 'FIXED_VERSION', 'OCP_COMPONENT', 'IMAGE', 'IMAGE_ROLE', 'SRPM', 'VEX_STATED'):
        if extra in df.columns:
            cols.append(extra)
    for col in cols:
        if col not in df.columns:
            df[col] = pd.Series(dtype=str)

    result_df = df[cols].copy()

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
        return priority * 10000 + sev * 100

    sort_series = result_df.apply(_sort_key, axis=1)
    result_df = result_df.iloc[sort_series.to_numpy().argsort()]
    if false_only:
        result_df = result_df[result_df['AUDIT_RESULT'] == '✅ FALSE POSITIVE']
    return result_df


# Engine literal for rung 8 (engine._decide_rpm, kind 'rpm_related_vuln').
# tests/test_engine_regressions.py case G pins this against engine drift.
_RELATED_MARKER = 'affected in related products'


def _is_stated(row) -> bool:
    """Did Red Hat actually state this verdict, or did the engine infer it?

    A verdict reached because the component is ABSENT from Red Hat's enumeration
    (VEX-MODEL §5g / rung 9) is the engine's reading of the errata policy, not a
    Red Hat claim.  Both render as "FALSE POSITIVE / Not affected", so without
    this split the table presents an inference as a vendor statement.  The
    OpenVEX emitter already gates on the same flag (openvex.statements_from_df).
    Bool survives CSV round-trips as the string "True"/"False".
    """
    return str(row.get('VEX_STATED', '')).strip().lower() in ('true', '1')


# A justification that OPENS with one of these was derived from a real Red Hat
# statement — just one that does not scope to this build/product, so the engine
# refuses to let it decide (VEX_STATED stays False).  Absence-derived verdicts
# open with "<component> not listed", "Not listed as affected", "No VEX statement".
# Matched as a prefix on purpose: "Not listed as affected; known_affected in RHEL
# 9 names other components only" mentions a status mid-string yet IS an absence
# verdict.
_STATEMENT_PREFIXES = (
    'known_not_affected', 'known_affected', 'under_investigation',
    'No affected entry', 'No supported Red Hat product affected',
    'Image build', 'This image build', 'Fixed in',
)


def _evidence_of(row) -> str:
    """Scope of Red Hat's claim: 'stated', 'other bld', 'related', 'not listed'.

    Red Hat's errata policy ("unless explicitly stated as not affected, all
    previous versions ... of a product listed here should be assumed vulnerable")
    only speaks about products it lists, so silence means different things
    depending on what Red Hat tracks:

      stated     — Red Hat says this about YOUR product/build; only kind published
      other bld  — Red Hat says it, but about another build/version of your product
      related    — Red Hat says it about a DIFFERENT product that ships the same
                   package (rung 8).  Kept open conservatively, but it is not a
                   statement about your product and must not read as one.
      not listed — absent from an enumeration that DOES cover this package type
      not listed — Red Hat's enumeration for this CVE does not name us.

    There is no separate bucket for Go/Python.  Red Hat does assess them — at the
    PRODUCT level (the operator or component image that ships the binary), which
    is exactly what the workload context is for.  The module purl is absent
    because that is not Red Hat's unit of assessment, not because the component
    is untracked; and since Red Hat DOES enumerate affected products, our
    product's absence carries the same meaning it does for an rpm.
    """
    just = str(row.get('JUSTIFICATION', '') or '').lstrip()
    # Checked BEFORE _is_stated: rung 8 (kind 'rpm_related_vuln') carries a real
    # Red Hat statement, so VEX_STATED is True — but the statement is about
    # another product that ships the same package, never about ours.  Labelling
    # it 'stated' would present a third-party claim as Red Hat's view of this
    # image, which is the one thing this tool must not do.
    if _RELATED_MARKER in just:
        return 'related'
    if _is_stated(row):
        return 'stated'
    if just.startswith(_STATEMENT_PREFIXES):
        return 'other bld'
    return 'not listed'


SYFT_DIR = os.path.join(BASE_DIR, "syft")


def _wire_go_owner_rpms(df: pd.DataFrame, ctx, image_ref: str) -> None:
    """Attach the vendoring rpm to each go-binary row of an RHACS scan.

    Red Hat assesses vendored Go at the rpm (or the component image), never the
    module purl, so this link is what lets a Go verdict reach rpm-level findings
    — and, just as importantly, what lets openvex.statements_from_df spot a
    divergent group and withhold a statement (a Go component cleared while its
    vendoring rpm is still open would otherwise suppress a real finding).

    RHACS components carry a `location` but their `executables` list comes back
    empty, so ownership is read from the syft SBOM already cached for the same
    digest.  Absent SBOM ⇒ no link, exactly as before.

    The same SBOM also supplies each binary rpm's SOURCE package, which the
    matcher needs: without it `libsmartcols` never reaches `util-linux`'s
    statements and reads as "not listed as affected" while the scanner paths —
    which get SRPM from the purl — correctly call it known_affected.  Both paths
    must decide alike.
    """
    if df is None or df.empty or not image_ref:
        return
    path = os.path.join(SYFT_DIR, image_ref.replace('/', '_') + '.json')
    if not os.path.exists(path):
        return
    try:
        owners = rpm_file_owners_from_sbom(path)
        srcs = rpm_source_map_from_sbom(path)
    except Exception:
        return
    if owners:
        wire_rpm_owners(df, ctx, owners)
    if srcs and 'COMPONENT' in df.columns:
        def _srpm_for(row):
            """Keep an SRPM the adapter already resolved; fill the rest."""
            have = str(row.get('SRPM', '') or '')
            if have and have.lower() not in ('nan', 'none'):
                return have
            return srcs.get(str(row.get('COMPONENT', '')), '')

        df['SRPM'] = df.apply(_srpm_for, axis=1)


_SCOPE_NOTE = {
    'other bld': 'other build',
    'not listed': 'not listed',
}


_RELATED_PRODUCTS_RE = re.compile(r'affected in related products \(([^)]*)\)')


def _related_product(just: str) -> str:
    """First product named by a rung-8 justification, shortened for the column.

    "(other product)" told the reader nothing — the whole question is WHICH
    product, and the engine already names it.
    """
    m = _RELATED_PRODUCTS_RE.search(just or '')
    if not m:
        return 'other product'
    first = m.group(1).split(',')[0].strip()
    first = re.sub(r'^Red Hat\s+', '', first)
    more = ', +' if ',' in m.group(1) else ''
    return (first[:26] + '…' if len(first) > 27 else first) + more


def _redhat_says(row) -> str:
    """What Red Hat says, in Red Hat's own vocabulary, qualified by scope.

    The State column already carries Red Hat's CVE-page wording (Affected, Not
    affected, Fixed, Will not fix, Fix deferred, Out of support scope).  What was
    missing is WHO it is about, which used to live in a second column of
    abstract words.  Folding the qualifier in keeps one column and one reading:
    an unqualified value is Red Hat's verdict on THIS build; anything in
    parentheses is not.
    """
    state = str(row.get('VEX_STATE', '') or '').strip() or '-'
    ev = _evidence_of(row)
    if ev == 'related':
        return f'{state} (in {_related_product(str(row.get("JUSTIFICATION", "")))})'
    note = _SCOPE_NOTE.get(ev)
    return f'{state} ({note})' if note else state


def _component_cell(row) -> str:
    """Component label, disambiguated by the binary a language module lives in.

    One image ships several Go binaries, each built with its own toolchain, and
    the scanner reports the module per binary — `stdlib` appears once for
    /usr/bin/virtctl (1.24.11) and again for /usr/local/bin/subctl (1.25.9).
    Printing the bare module name makes those look like duplicate rows with
    contradictory verdicts, when they are different artefacts.  rpm rows are left
    alone: their location is always var/lib/rpm and adds nothing.
    """
    comp = str(row.get('COMPONENT', ''))
    src = str(row.get('SOURCE', '') or '').strip().upper()
    if src in ('', 'OS'):
        return comp
    loc = str(row.get('LOCATION', '') or '').strip()
    binary = os.path.basename(loc) if loc else ''
    if binary and binary not in comp:
        return f'{comp} @{binary}'
    return comp


def _render_triage_table(console: Console, result_df: pd.DataFrame, ctx,
                         source_label: str = 'RHACS',
                         actionable_only: bool = False) -> None:
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
            'comp': _component_cell(row),
            'rhacs': str(row.get('RHACS_SEVERITY', 'Unknown')),
            'vex': str(row.get('SEVERITY', 'Unknown')),
            'verdict': verdict_mark,
            'verdict_plain': verdict_plain,
            'state': _redhat_says(row),
            'evidence': _evidence_of(row),
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
    for droppable in ('rhacs', 'vex', 'fix', 'just', 'state'):
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
        if key == 'evidence':
            return {'stated': 'green', 'other bld': 'cyan', 'related': 'magenta',
                    'not listed': 'yellow'}.get(r['evidence'], 'dim')
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

    rhacs_counts = Counter(r['rhacs'] for r in rows_all)
    rhacs_str = ", ".join(f"{n} {s}" for s, n in
                          sorted(rhacs_counts.items(), key=lambda kv: _sev_rank.get(kv[0], 9)))
    sev_shift = sum(1 for r in rows_all if r['rhacs'] not in ('Unknown', r['vex']))

    label = ctx.image_ref or ctx.display_name
    m = re.search(r'@sha256:([a-f0-9]{6})', label or '')
    if m:
        label = re.sub(r'@sha256:[a-f0-9]+', f" (sha256:{m.group(1)}...)", label)
    fp_ev = Counter(r['evidence'] for r in rows_all
                    if r['verdict_plain'] == 'FALSE POSITIVE')
    fp_stated = fp_ev['stated']

    console.print(f"\nImage: [bold cyan]{label}[/bold cyan]")
    console.print(
        f"[bold]{total}[/bold] findings → [bold green]{fp} false positives[/bold green] "
        f"({100 * fp // total}%), [bold red]{pos} real[/bold red]."
    )
    if fp:
        console.print(
            f"  of those: [green]{fp_ev['stated']}[/green] cleared by Red Hat for this build "
            f"(published as OpenVEX), [dim]{fp - fp_stated} not listed / other scope[/dim]."
        )
    if hidden:
        console.print(f"  [dim]{hidden} false positive row(s) hidden — --false-only to see "
                      f"them, --all-rows for everything; exports always contain all rows.[/dim]")
    if sev_shift:
        console.print(f"[yellow]{sev_shift} finding(s) rated differently by Red Hat VEX than by the scanner.[/yellow]")
    console.print()


def _audit_and_display(df: pd.DataFrame, ctx, console: Console, *,
                       output_path: Optional[str] = None, output_fmt: str = "csv",
                       false_only: bool = False, show_all: bool = False,
                       source_label: str = "RHACS") -> pd.DataFrame:
    """Sync VEX, run audit, render table, print summary, optionally write output."""
    unique_cves = [c.strip().upper() for c in df['CVE'].unique()]
    cached  = sum(1 for c in unique_cves if os.path.exists(os.path.join(VEX_DIR, f"{c}.json")))
    to_fetch = len(unique_cves) - cached
    # Only say something when there is something to wait for — a fully cached
    # run should print nothing until it has an answer.
    if to_fetch:
        console.print(f"🔄 syncing {to_fetch} CVEs from Red Hat...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(download_and_convert_with_lib, c): c for c in unique_cves}
        for f in as_completed(futures):
            pass
    if not df.empty:
        df['RHACS_SEVERITY'] = df['SEVERITY'].apply(
            lambda s: _RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown'))

    if df.empty:
        console.print("[yellow]⚠  No CVE findings to audit.[/yellow]")
        for col in ['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE',
                    'VEX_STATED', 'VEX_PRODUCT', 'RHACS_SEVERITY', 'SEVERITY_MISMATCH']:
            df[col] = pd.Series(dtype=str)
    else:
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE',
            'VEX_STATED']] = df.apply(
            lambda row: list(audit_row_detailed(row, ctx)), axis=1, result_type='expand')
        df['VEX_PRODUCT'] = df.apply(lambda row: _vex_product_for_row(row, ctx), axis=1)
        df['SEVERITY_MISMATCH'] = (
            (df['RHACS_SEVERITY'] != 'Unknown') & (df['SEVERITY'] != df['RHACS_SEVERITY']))

    result_df = _sort_and_filter_df(df, false_only)
    # The terminal shows what you can act on; the exported file keeps every row.
    # False positives are the ones you do NOT have to touch, so listing thousands
    # of them buries the handful that need work — they are counted in the footer
    # instead.  --false-only flips this, --all-rows shows both.
    _render_triage_table(console, result_df, ctx, source_label,
                         actionable_only=not (false_only or show_all))

    if output_path and output_fmt != "table":
        _write_output(result_df, output_path, output_fmt, console)

    return result_df


def _audit_silent(df: pd.DataFrame, ctx, false_only: bool = False,
                  vex_product: bool = True) -> pd.DataFrame:
    """Run VEX sync + audit and return a sorted result DataFrame — no console output.

    vex_product=False skips the VEX_PRODUCT display column — a second
    full-document scan per row that nearly doubles audit time.  Callers that
    only feed openvex.statements_from_df (the generate path) never read it.
    """
    unique_cves = [c.strip().upper() for c in df['CVE'].unique()]
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        for f in as_completed({ex.submit(download_and_convert_with_lib, c): c for c in unique_cves}):
            pass

    if not df.empty:
        df['RHACS_SEVERITY'] = df['SEVERITY'].apply(
            lambda s: _RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown'))
        df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY', 'VEX_STATE',
            'VEX_STATED']] = df.apply(
            lambda row: list(audit_row_detailed(row, ctx)), axis=1, result_type='expand')
        df['VEX_PRODUCT'] = (df.apply(lambda row: _vex_product_for_row(row, ctx), axis=1)
                             if vex_product else '')
        df['SEVERITY_MISMATCH'] = (
            (df['RHACS_SEVERITY'] != 'Unknown') & (df['SEVERITY'] != df['RHACS_SEVERITY']))

    return _sort_and_filter_df(df, false_only)


def _fetch_and_audit(session, image_ref: str, image_id: Optional[str],
                     false_only: bool, release_ocp_ver: Optional[str] = None,
                     force: bool = False, comp_name: Optional[str] = None) -> dict:
    """Fetch image scan from RHACS and run a silent audit.

    image_id=None → search RHACS by digest first (OCP mode).
    release_ocp_ver → overrides per-image CPE OCP version (--ocp mode).
    Returns a dict with keys: found, img_ctx, os_info, result_df, sbom_summary, error.
    """
    try:
        if image_id is None:
            try:
                image_data = rhacs_scan_image(session, image_ref, force=force)
            except TypeError:
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
        os_info    = (image_data.get("scan") or {}).get("operatingSystem", "")
        # os_info first: it is the scanner's own read of the image and outranks
        # labels and path (art-dev images ship no labels at all, so without it
        # they silently keep rhel_ver='8' — 92 of 13,136 scans).
        img_ctx    = parse_context_from_labels(labels, image_ref, os_info) if labels \
            else parse_image_ref(image_ref, os_hint=os_info)

        if release_ocp_ver:
            minor_ver = '.'.join(release_ocp_ver.split('.')[:2])
            img_ctx.workload_type = "ocp"
            img_ctx.ocp_ver = minor_ver
            os_rhel = re.search(r'(?:rhel|coreos):(\d+)', os_info or '')
            if os_rhel:
                img_ctx.rhel_ver = os_rhel.group(1)
            elif comp_name:
                cn_rhel = re.search(r'(?:rhel-[^-]+-|rhel-)(\d+)$', comp_name)
                if cn_rhel:
                    img_ctx.rhel_ver = cn_rhel.group(1)
            img_ctx.display_name = f"OpenShift {release_ocp_ver}"
            img_ctx.extra_prefixes = []
            if comp_name:
                img_ctx.ocp_component = comp_name

        try:
            _sbom = rhacs_get_sbom(session, image_ref, force=force)
            img_ctx.sbom_src_map = _build_sbom_src_map(_sbom)
            img_ctx.sbom_packages = _build_sbom_packages(_sbom)
        except Exception:
            pass

        img_df = rhacs_to_df(image_data)
        if img_df.empty:
            return {"found": True, "img_ctx": img_ctx, "os_info": os_info,
                    "result_df": None, "sbom_summary": None, "error": None}

        _wire_go_owner_rpms(img_df, img_ctx, image_ref)
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
    parser.add_argument("target",     nargs="?", default=None,
                        help="Image ref or RHACS scan CSV file — same positional as\n"
                             "'vextriage grype/trivy'. A path that exists is treated as\n"
                             "--scan, anything else as --image.")
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

    if args.target:
        if os.path.exists(args.target):
            if args.scan and args.scan != args.target:
                parser.error("positional target and --scan point to different files")
            args.scan = args.target
        else:
            if args.image and args.image != args.target:
                parser.error("positional target and --image name different images")
            args.image = args.target

    if args.namespace and args.image:
        parser.error("--namespace and --image are mutually exclusive")
    if args.ocp and (args.image or args.namespace):
        parser.error("--ocp cannot be combined with --image or --namespace")

    _console = Console()

    ROX_ENDPOINT  = os.environ.get("ROX_ENDPOINT", "")
    ROX_API_TOKEN = os.environ.get("ROX_API_TOKEN", "")

    use_namespace = (args.namespace is not None and bool(ROX_ENDPOINT)
                     and bool(ROX_API_TOKEN) and args.scan is None)
    use_ocp = (args.ocp is not None and bool(ROX_ENDPOINT) and bool(ROX_API_TOKEN))
    use_sbom = (getattr(args, 'sbom', False) and args.image is not None
                and bool(ROX_ENDPOINT) and bool(ROX_API_TOKEN))
    use_show_scan = (getattr(args, 'show_scan', False) and args.image is not None
                     and bool(ROX_ENDPOINT) and bool(ROX_API_TOKEN))
    use_api = (args.image is not None and bool(ROX_ENDPOINT) and bool(ROX_API_TOKEN)
               and args.scan is None and not use_namespace and not use_ocp)

    if args.ocp is not None and not use_ocp:
        _console.print("[red]Error:[/red] --ocp requires ROX_ENDPOINT and ROX_API_TOKEN environment variables.")
        raise SystemExit(1)
    if args.namespace is not None and not use_namespace:
        _console.print("[red]Error:[/red] --namespace requires ROX_ENDPOINT and ROX_API_TOKEN environment variables.")
        raise SystemExit(1)

    if use_ocp or use_namespace or use_api or use_sbom or use_show_scan:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ctx = WorkloadContext(rhel_ver="8", workload_type="ubi", display_name="UBI8")
    if args.image:
        ctx = parse_image_ref(args.image)
        _console.print(f"\n[bold]Image:[/bold] {args.image}")

    # ── SBOM mode ──
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

            tbl = Table(title=f"SBOM Packages — [bold cyan]{args.image}[/bold cyan]",
                        box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=False)
            tbl.add_column("Package",  style="cyan",    no_wrap=True)
            tbl.add_column("Version",  style="dim",     no_wrap=False, max_width=40)
            tbl.add_column("Purpose",  style="magenta", no_wrap=True)
            tbl.add_column("File",     style="dim",     no_wrap=False, max_width=45)
            for _, row in pkgs_df.iterrows():
                tbl.add_row(row["NAME"], row["VERSION"], row["PURPOSE"], row["FILE"])
            _console.print(tbl)
            _console.print()
        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)
        if not use_api:
            raise SystemExit(0)

    # ── Show-scan mode ──
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
            tbl = Table(title=f"Scan — [bold cyan]{args.image}[/bold cyan]",
                        box=box.ROUNDED, show_header=True, header_style="bold white", show_lines=False)
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
                tbl.add_row(comp.get("name", ""), comp.get("version", ""), comp.get("source", ""),
                            str(cve_n) if cve_n else "-",
                            f"[{sev_style}]{sev_disp}[/{sev_style}]" if sev_disp else "-")
            _console.print(tbl)
            _console.print()
        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)
        if not use_api:
            raise SystemExit(0)

    # ── OCP release mode ──
    if use_ocp:
        if not os.path.exists(args.ocp):
            _console.print(f"[bold red]❌ Pullspecs file not found: {args.ocp}[/bold red]")
            raise SystemExit(1)

        images: list = []
        seen_digests: set = set()
        _manifest_ocp_ver: Optional[str] = None
        with open(args.ocp) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith('Pull From:'):
                    continue
                nm = re.match(r'^Name:\s+(\d+\.\d+(?:\.\d+)*)', line)
                if nm and _manifest_ocp_ver is None:
                    _manifest_ocp_ver = nm.group(1)
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
                       f"file=[cyan]{args.ocp}[/cyan]  endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        _console.print(f"✅ Parsed [bold]{len(images)}[/bold] unique component image(s) from release manifest")
        _console.print()

        try:
            session = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            total   = len(images)
            results_map: dict = {}
            not_found: list   = []
            _console.print(f"🚀 Scanning {total} images with [bold]{args.workers}[/bold] parallel workers...\n")
            _force = getattr(args, 'force', False)

            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                future_to_comp = {
                    ex.submit(_fetch_and_audit, session, image_ref, None,
                              args.false_only, _manifest_ocp_ver, _force, comp_name):
                        (comp_name, image_ref)
                    for comp_name, image_ref in images}
                done = 0
                for future in as_completed(future_to_comp):
                    done += 1
                    comp_name, image_ref = future_to_comp[future]
                    res = future.result()
                    results_map[comp_name] = (image_ref, res)
                    status = "✅" if res.get("found") else ("⚠ " if res.get("found") is False else "❌")
                    suffix = ""
                    if res.get("found") is False:
                        suffix = f"  [dim]{image_ref}[/dim]"
                    elif res.get("found") is None and res.get("error"):
                        suffix = f"  [red]{res['error'][:80]}[/red]"
                    _console.print(f"  [{done}/{total}] {status} {comp_name}{suffix}", highlight=False)

            failed = [(cn, ir) for cn, ir in images
                      if results_map.get(cn, (None, {}))[1].get("found") is None]
            if failed:
                _console.print(f"\n[yellow]⚠  {len(failed)} image(s) failed — retrying...[/yellow]")
                time.sleep(5)
                with ThreadPoolExecutor(max_workers=args.workers) as ex:
                    retry_futures = {
                        ex.submit(_fetch_and_audit, session, ir, None,
                                  args.false_only, _manifest_ocp_ver, True, cn): (cn, ir)
                        for cn, ir in failed}
                    for future in as_completed(retry_futures):
                        cn, ir = retry_futures[future]
                        res = future.result()
                        results_map[cn] = (ir, res)
                        status = "✅" if res.get("found") else ("⚠ " if res.get("found") is False else "❌")
                        _console.print(f"  [retry] {status} {cn}", highlight=False)

            _console.print()

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

            if still_failed:
                _console.print(f"[yellow]⚠  Exiting with code 2 — {len(still_failed)} image(s) still failed.[/yellow]")
                raise SystemExit(2)
            raise SystemExit(0)

        except requests.RequestException as e:
            _console.print(f"[bold red]❌ RHACS API error: {e}[/bold red]")
            raise SystemExit(1)

    # ── Namespace mode ──
    if use_namespace:
        _console.print(f"\n[bold]Mode:[/bold] [cyan]RHACS API / namespace[/cyan]  "
                       f"endpoint=[cyan]{ROX_ENDPOINT}[/cyan]  namespace=[cyan]{args.namespace}[/cyan]")
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
                    for image_ref, image_id in images}
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

    # ── Single-image API mode or CSV mode ──
    session = None
    if use_api:
        _console.print(f"[bold]Mode:[/bold] [cyan]RHACS API[/cyan]  endpoint=[cyan]{ROX_ENDPOINT}[/cyan]")
        try:
            session    = _rhacs_session(ROX_ENDPOINT, ROX_API_TOKEN)
            _force     = getattr(args, 'force', False)
            _console.print("📥 Fetching scan data...")
            image_data = rhacs_scan_image(session, args.image, force=_force)
            if not image_data:
                _console.print(f"[bold red]❌ Could not scan image: {args.image}[/bold red]")
                raise SystemExit(1)

            labels = (image_data.get("metadata") or {}).get("v1", {}).get("labels") or {}
            os_info = (image_data.get("scan") or {}).get("operatingSystem", "")
            if labels:
                ctx = parse_context_from_labels(labels, args.image, os_info)
            elif os_info:
                ctx = parse_image_ref(args.image, os_hint=os_info)

            df = rhacs_to_df(image_data)
            _wire_go_owner_rpms(df, ctx, args.image)
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
        scan_file = args.scan or SCAN_FILE
        if not os.path.exists(scan_file):
            _console.print(f"[bold red]❌ '{scan_file}' not found.[/bold red]")
            _console.print("  Set ROX_ENDPOINT + ROX_API_TOKEN env vars and use --image for API mode,")
            _console.print("  or provide a scan CSV with --scan.")
            raise SystemExit(1)
        _console.print(f"[bold]Mode:[/bold] [cyan]CSV[/cyan]  file=[cyan]{scan_file}[/cyan]")
        df = pd.read_csv(scan_file)

    _console.print(f"[bold]Context:[/bold] type=[cyan]{ctx.workload_type}[/cyan]  "
                   f"rhel=[cyan]{ctx.rhel_ver}[/cyan]  display=[cyan]{ctx.display_name}[/cyan]")
    if ctx.extra_prefixes:
        _console.print(f"[bold]VEX scope:[/bold] {', '.join(ctx.extra_prefixes[:6])}")
    _console.print()

    _out_path = args.output if args.output and args.output_fmt != "table" else None
    result_df = _audit_and_display(df, ctx, _console, output_path=_out_path,
                                   output_fmt=args.output_fmt, false_only=args.false_only)

    if use_api and session is not None and result_df is not None and not result_df.empty:
        _console.print("🔍 Verifying component versions against SBOM...")
        sbom_s = _verify_sbom_against_df(session, args.image, result_df)
        _print_sbom_summary(_console, sbom_s)


if __name__ == "__main__":
    main()
