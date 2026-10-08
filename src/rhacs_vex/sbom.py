"""The image's syft-json SBOM — parsed once, read by every scan path.

The SBOM supplies what a scanner report does not, and what Red Hat's way of
publishing VEX requires:

  * labels and the per-arch manifest digest — the workload's identity
    (VEX PIDs carry per-arch digests, the pull ref the manifest-list one);
  * binary rpm → source rpm (`libsmartcols` → `util-linux`): Red Hat often
    tracks a subpackage under its source;
  * file → owning rpm: Red Hat assesses vendored Go at the rpm that ships the
    binary (golang.org/x/net in /usr/bin/buildah → `buildah`), never at the
    module purl, so a Go finding needs its owning rpm to reach the statement;
  * installed versions, to verify the scanner's version claims.
"""
from __future__ import annotations

import json
import os
import re
from typing import Optional

SYFT_DIR = os.path.join('data', 'syft')
_UPSTREAM_RE = re.compile(r'upstream=([^&]+?)-[^-]+-[^-]+\.src\.rpm')


def syft_path(image_ref: str) -> str:
    """Where the syft-json SBOM of a (digest-pinned) image is cached."""
    return os.path.join(SYFT_DIR, image_ref.replace('/', '_') + '.json')


def srpm_from_purl(purl: str) -> str:
    """Source rpm name from an rpm purl's `upstream=` qualifier ('' if none)."""
    m = _UPSTREAM_RE.search(purl or '')
    return m.group(1) if m else ''


class SyftSBOM:
    """Read-only view over one syft-json document."""

    def __init__(self, doc: dict, path: str = ''):
        self.path = path
        self.doc = doc or {}
        self.artifacts = self.doc.get('artifacts') or []
        md = (self.doc.get('source') or {}).get('metadata') or {}
        self.labels: dict = md.get('labels') or {}
        self.digests: list = [d for d in [md.get('manifestDigest') or '',
                                          *(md.get('repoDigests') or [])] if d]

    @classmethod
    def load(cls, path: str) -> Optional["SyftSBOM"]:
        try:
            with open(path) as fh:
                return cls(json.load(fh), path)
        except Exception:
            return None

    @classmethod
    def for_image(cls, image_ref: str) -> Optional["SyftSBOM"]:
        """The cached SBOM for an image ref, if one exists."""
        path = syft_path(image_ref)
        return cls.load(path) if os.path.exists(path) else None

    def os_hint(self) -> str:
        """'rhel:9.4' from syft's distro block ('' when absent)."""
        d = self.doc.get('distro') or {}
        return f"{d.get('id') or d.get('name') or ''}:{d.get('versionID') or d.get('version') or ''}" \
            if d else ''

    # ── derived maps ────────────────────────────────────────────────────────
    def image_ref(self) -> str:
        """`repo@sha256:…` this SBOM was taken from ('' when unknown)."""
        md = (self.doc.get('source') or {}).get('metadata') or {}
        for d in md.get('repoDigests') or []:
            if '@sha256:' in d:
                return d
        return ''

    def rpms(self):
        return [a for a in self.artifacts if a.get('type') == 'rpm' and a.get('name')]

    def source_rpms(self) -> dict:
        """binary rpm name → source rpm name (only where they differ)."""
        out = {}
        for a in self.rpms():
            src = srpm_from_purl(a.get('purl') or '')
            if src and src != a['name']:
                out[a['name']] = src
        return out

    def file_owners(self) -> dict:
        """file path → (rpm name, version-release) for every rpm-owned file."""
        owners = {}
        for a in self.rpms():
            ver = re.sub(r'^\d+:', '', str(a.get('version', '')))
            if not ver:
                continue
            for f in (a.get('metadata') or {}).get('files') or []:
                path = f.get('path') if isinstance(f, dict) else str(f)
                if path:
                    owners[path] = (a['name'], ver)
        return owners

    def package_versions(self) -> dict:
        """package name → {versions} across every artifact type."""
        out: dict = {}
        for a in self.artifacts:
            if a.get('name') and a.get('version'):
                out.setdefault(a['name'], set()).add(str(a['version']))
        return out

    def enrich(self, df, ctx) -> None:
        """Attach SRPM / OWNER_RPM to findings and SBOM maps to the context."""
        wire_rpm_owners(df, ctx, self.file_owners())
        srcs = self.source_rpms()
        if srcs and df is not None and not df.empty and 'COMPONENT' in df.columns:
            def srpm_for(row):
                have = str(row.get('SRPM', '') or '')
                if have and have.lower() not in ('nan', 'none'):
                    return have
                return srcs.get(str(row.get('COMPONENT', '')), '')
            df['SRPM'] = df.apply(srpm_for, axis=1)


def wire_rpm_owners(df, ctx, owners: dict) -> None:
    """Link each non-rpm finding to the rpm that owns its binary.

    - df['OWNER_RPM'] = 'name@version-release' (the OpenVEX emitter uses it to
      withhold a Go clear while the vendoring rpm is still open);
    - ctx.sbom_src_map[component] = rpm name, so the engine matches the rpm's
      statements.  A component found in binaries of two different rpms stays
      unmapped — one verdict row cannot represent diverging owners.

    syft paths are absolute, RHACS locations relative; both are indexed.
    """
    if df is None or df.empty or not owners:
        return
    norm = {}
    for path, owner in owners.items():
        p = str(path)
        norm[p] = norm['/' + p.lstrip('/')] = norm[p.lstrip('/')] = owner

    def owner_of(r):
        loc = str(r.get('LOCATION', ''))
        if str(r.get('SOURCE', '')).strip().upper() != 'OS' and loc in norm:
            return '{}@{}'.format(*norm[loc])
        return ''

    df['OWNER_RPM'] = df.apply(owner_of, axis=1)
    src_map, conflict = {}, set()
    for comp, owner in zip(df['COMPONENT'].astype(str), df['OWNER_RPM']):
        if not owner:
            continue
        name = owner.split('@')[0]
        if src_map.get(comp, name) != name:
            conflict.add(comp)
        src_map.setdefault(comp, name)
    for c in conflict:
        src_map.pop(c, None)
    ctx.sbom_src_map = {**src_map, **(ctx.sbom_src_map or {})}
