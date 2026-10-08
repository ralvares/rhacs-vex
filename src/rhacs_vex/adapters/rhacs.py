"""RHACS Central as a finding source.

RHACS proposes the (component, CVE) pairs and supplies the image's labels, OS
and SPDX SBOM; the engine decides.  Responses are cached as plain JSON under
data/scans/ and data/sbom/: a digest-pinned image is content-addressed, so its
cache never expires, and a tag ref is reused for LOCAL_CACHE_TTL.  That cache
is also what makes `--offline` (re-triage without Central) possible.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from typing import Optional

import pandas as pd
import requests

from ..core.workload import WorkloadContext, context_for_image

SCAN_DIR = os.path.join('data', 'scans')
SBOM_DIR = os.path.join('data', 'sbom')
LOCAL_CACHE_TTL = 24 * 3600

COLUMNS = ['COMPONENT', 'VERSION', 'CVE', 'SEVERITY', 'CVSS', 'LINK', 'FIXED_VERSION',
           'SOURCE', 'LOCATION', 'ADVISORY', 'ADVISORY_LINK']


class Central:
    """A thin RHACS API client: bearer token, retries, JSON file cache."""

    def __init__(self, endpoint: str, token: str, *, offline: bool = False):
        self.base = f"https://{endpoint}" if endpoint else ''
        self.configured = bool(endpoint and token)
        self.offline = offline
        self.http = requests.Session()
        self.http.headers.update({"Authorization": f"Bearer {token}",
                                  "Accept": "application/json"})
        self.http.verify = False              # Central commonly has a self-signed cert
        if endpoint:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @classmethod
    def from_env(cls, *, offline: bool = False) -> "Central":
        return cls(os.environ.get("ROX_ENDPOINT", ""), os.environ.get("ROX_API_TOKEN", ""),
                   offline=offline)

    def _call(self, method: str, path: str, *, retries: int = 3, **kw) -> dict:
        """One API call with exponential backoff on timeouts and 5xx."""
        if self.offline:
            raise RuntimeError('offline: not calling RHACS Central')
        delay = 10.0
        for attempt in range(retries + 1):
            try:
                resp = self.http.request(method, self.base + path, **kw)
                resp.raise_for_status()
                return resp.json()
            except (requests.Timeout, requests.ConnectionError):
                if attempt == retries:
                    raise
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else 0
                if status < 500 or attempt == retries:
                    raise
            time.sleep(delay)
            delay *= 2
        raise RuntimeError('unreachable')

    # ── images ──────────────────────────────────────────────────────────────
    def scan(self, image_ref: str, force: bool = False) -> Optional[dict]:
        """Scan result for an image ref (POST /v1/images/scan), cached."""
        path = scan_cache_path(image_ref)
        if not force:
            cached = _read_cache(path, image_ref)
            if cached is not None or self.offline:
                return cached
        data = self._call('POST', '/v1/images/scan', timeout=120,
                          json={"imageName": image_ref, "force": force})
        if not data.get('id'):
            return None
        _write_cache(path, data)
        return data

    def image(self, image_id: str, image_ref: str = '', force: bool = False) -> dict:
        """Full image detail by RHACS image id, cached under the ref."""
        path = scan_cache_path(image_ref or image_id)
        if not force:
            cached = _read_cache(path, image_ref)
            if cached is not None or self.offline:
                return cached
        data = self._call('GET', f'/v1/images/{image_id}', timeout=60,
                          params={"stripDescription": True})
        _write_cache(path, data)
        return data

    def sbom(self, image_ref: str, force: bool = False) -> Optional[dict]:
        """The image's SPDX 2.3 SBOM, cached."""
        path = sbom_cache_path(image_ref)
        if not force:
            cached = _read_cache(path, image_ref)
            if cached is not None or self.offline:
                return cached
        data = self._call('POST', '/api/v1/images/sbom', timeout=120,
                          json={"imageName": image_ref, "force": force})
        _write_cache(path, data)
        return data

    def namespace_images(self, namespace: str) -> list:
        """(full image name, image id) for every image deployed in a namespace."""
        data = self._call('GET', '/v1/images', timeout=30,
                          params={"query": f"Namespace:{namespace}", "pagination.limit": 1000})
        seen = {}
        for img in data.get("images", []):
            name = img.get("name", "")
            full = name if isinstance(name, str) else (name or {}).get("fullName", "")
            if full and img.get("id") and full not in seen:
                seen[full] = img["id"]
        return list(seen.items())


# ── cache ────────────────────────────────────────────────────────────────────

def _safe(name: str) -> str:
    return re.sub(r'[^\w@:.+-]', '_', name)


def scan_cache_path(image_ref: str) -> str:
    return os.path.join(SCAN_DIR, f"{_safe(image_ref)}.json")


def sbom_cache_path(image_ref: str) -> str:
    return os.path.join(SBOM_DIR, f"{_safe(image_ref)}.sbom")


def _read_cache(path: str, image_ref: str) -> Optional[dict]:
    try:
        if '@sha256:' in (image_ref or ''):
            fresh = os.path.getsize(path) > 0
        else:
            fresh = time.time() - os.path.getmtime(path) < LOCAL_CACHE_TTL
        if fresh:
            with open(path) as fh:
                return json.load(fh)
    except (OSError, ValueError):
        pass
    return None


def _write_cache(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix='.tmp')
    with os.fdopen(fd, 'w') as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


# ── scan → findings / context ────────────────────────────────────────────────

def scan_to_df(image_data: dict) -> pd.DataFrame:
    """One row per (component, version, CVE) of an RHACS scan."""
    rows, seen = [], set()
    for comp in (image_data.get("scan") or {}).get("components", []):
        name, ver = comp.get("name", ""), comp.get("version", "")
        for vuln in comp.get("vulns", []):
            cve = (vuln.get("cve") or "").upper().strip()
            if not cve or (name, ver, cve) in seen:
                continue
            seen.add((name, ver, cve))
            rows.append({
                "COMPONENT": name, "VERSION": ver, "CVE": cve,
                "SEVERITY": vuln.get("severity") or "",
                "CVSS": vuln.get("cvss") or 0,
                "LINK": vuln.get("link") or "",
                "FIXED_VERSION": vuln.get("fixedBy", "") or comp.get("fixedBy", ""),
                "SOURCE": comp.get("source", ""),
                "LOCATION": comp.get("location", ""),
                "ADVISORY": "", "ADVISORY_LINK": "",
            })
    return pd.DataFrame(rows, columns=COLUMNS)


def labels_of(image_data: dict) -> dict:
    return ((image_data.get("metadata") or {}).get("v1") or {}).get("labels") or {}


def os_of(image_data: dict) -> str:
    return (image_data.get("scan") or {}).get("operatingSystem", "") or ""


def context_for_scan(image_ref: str, image_data: dict, *, ocp_release: str = None,
                     ocp_component: str = None) -> WorkloadContext:
    """The workload context for an RHACS-scanned image.

    The scan's operatingSystem is RHACS's own read of /etc/redhat-release and
    outranks labels and path (art-dev payload images ship no labels at all).
    """
    return context_for_image(image_ref, os_hint=os_of(image_data),
                             labels=labels_of(image_data), ocp_release=ocp_release,
                             ocp_component=ocp_component)


# ── SPDX (RHACS serves SPDX 2.3, not syft-json) ──────────────────────────────

def spdx_source_rpms(sbom: dict) -> dict:
    """binary package → source package, from GENERATED_FROM relationships."""
    by_id = {p.get("SPDXID"): p for p in sbom.get("packages", []) if p.get("SPDXID")}
    out = {}
    for rel in sbom.get("relationships", []):
        if rel.get("relationshipType") != "GENERATED_FROM":
            continue
        b, s = by_id.get(rel.get("spdxElementId")), by_id.get(rel.get("relatedSpdxElement"))
        if b and s and b.get("name") and s.get("name") and b["name"] != s["name"]:
            out[b["name"]] = s["name"]
    return out


def spdx_packages(sbom: dict) -> dict:
    """package name → {versions}."""
    out: dict = {}
    for p in sbom.get("packages", []):
        if p.get("name"):
            out.setdefault(p["name"], set()).add(p.get("versionInfo", ""))
    return out
