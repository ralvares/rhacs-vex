"""context.py — WorkloadContext for images scanned outside RHACS.

RHACS scans carry image labels in their metadata; grype/trivy flows don't, so
the labels come from `skopeo inspect` (same authenticated registry access the
pipeline already relies on).  Falls back to pure image-ref parsing when the
registry is unreachable — same degradation the offline retriage path uses.
"""
from __future__ import annotations

import json
import re
import subprocess
from typing import Optional

from .engine import WorkloadContext, parse_context_from_labels, parse_image_ref


def _skopeo_labels(image_ref: str) -> dict:
    """Image labels via `skopeo inspect` (linux platform), {} on any failure."""
    for extra in (['--override-os', 'linux'],
                  ['--override-os', 'linux', '--override-arch', 'amd64']):
        try:
            out = subprocess.run(
                ['skopeo', 'inspect', *extra, f'docker://{image_ref}'],
                capture_output=True, text=True, timeout=120)
            if out.returncode == 0:
                return json.loads(out.stdout).get('Labels') or {}
        except Exception:
            pass
    return {}


def context_for_image(image_ref: str, *, os_hint: Optional[str] = None,
                      labels: Optional[dict] = None) -> WorkloadContext:
    """Build the triage WorkloadContext for a digest-pinned image ref.

    os_hint is the scanner's OS/distro string (grype `distro`, trivy
    `Metadata.OS`) and refines rhel_ver the same way the RHACS path uses the
    scan's operatingSystem field.
    """
    if labels is None:
        labels = _skopeo_labels(image_ref)
    ctx = parse_context_from_labels(labels, image_ref) if labels \
        else parse_image_ref(image_ref)
    if os_hint:
        m = re.search(r'(?:rhel|coreos|redhat)[^0-9]{0,3}(\d+)', str(os_hint).lower())
        if m:
            ctx.rhel_ver = m.group(1)
    return ctx
