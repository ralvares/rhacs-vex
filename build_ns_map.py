#!/usr/bin/env python3
"""
build_ns_map.py — Generate data/ns_vex_prefixes.json from Red Hat operator index catalogs.

Reads every catalog*.json file in data/catalogs/, parses olm.bundle entries
and extracts:
  - registry namespace  (from the bundle image URL)
  - OLM package name
  - Operator display name  (from olm.csv.metadata.displayName)

All three are normalised to snake_case VEX-prefix candidates and merged per namespace.
The result is written to data/ns_vex_prefixes.json and used by triage.py at runtime
to scope VEX product-ID matching for operator images — replacing the old hardcoded table.

Usage:
  python3 build_ns_map.py [catalog*.json ...]

  With no arguments, all catalog*.json files in data/catalogs/ are processed.
"""

import json
import os
import re
import sys
import glob

# Prefix patterns stripped from displayNames before normalising so that
# "Red Hat OpenShift Pipelines" → "pipelines" rather than "red_hat_openshift_pipelines"
# (both variants are kept — stripping just produces shorter, more useful candidates).
_STRIP_RE = re.compile(
    r'^('
    r'red\s+hat\s+integration\s*[-–]\s*'
    r'|red\s+hat\s+openshift\s+'
    r'|red\s+hat\s+build\s+of\s+'
    r'|red\s+hat\s+'
    r'|redhat\s+'
    r')',
    re.IGNORECASE,
)


def _normalise(text: str) -> list[str]:
    """
    Return a de-duplicated list of snake_case prefix candidates for *text*.
    Generates multiple variants: raw, stripped of "Red Hat …" prefixes,
    and with trailing version tokens removed.
    """
    candidates: set[str] = set()
    text = text.strip()
    if not text:
        return []

    def _snake(s: str) -> str:
        # Remove parenthetical suffixes: "(Technical Preview)", "(Multiarch)"…
        s = re.sub(r'\s*\(.*?\)', '', s)
        # Collapse any non-alphanumeric run to underscore
        s = re.sub(r'[^a-z0-9]+', '_', s.lower())
        return s.strip('_')

    raw = _snake(text)
    if raw:
        candidates.add(raw)

    stripped = _STRIP_RE.sub('', text).strip()
    if stripped and stripped.lower() != text.lower():
        s = _snake(stripped)
        if s:
            candidates.add(s)

    # Strip trailing version token(s): "AMQ Streams 2.x" → "amq_streams"
    for c in list(candidates):
        trimmed = re.sub(r'(_\d[\d.x]*)+$', '', c).strip('_')
        if trimmed and trimmed != c:
            candidates.add(trimmed)

    return sorted(candidates)


def _namespace_from_image(image_url: str) -> str | None:
    """Extract the registry namespace from a full image reference."""
    m = re.match(r'[^/]+/([^/@:]+)', image_url)
    return m.group(1) if m else None


def _parse_catalog(path: str) -> dict[str, set[str]]:
    """
    Parse one catalog JSON file and return {namespace: set_of_prefix_candidates}.
    The catalog is a series of concatenated JSON objects separated by blank lines /
    newlines — not a JSON array — so we split on top-level '{' boundaries.
    """
    with open(path) as fh:
        content = fh.read()

    parts = re.split(r'\n(?=\{)', content)
    ns_candidates: dict[str, set[str]] = {}

    for part in parts:
        try:
            obj = json.loads(part)
        except json.JSONDecodeError:
            continue

        if obj.get('schema') != 'olm.bundle':
            continue

        image = obj.get('image', '')
        ns = _namespace_from_image(image)
        if not ns:
            continue

        bag = ns_candidates.setdefault(ns, set())

        # 1. OLM package name (normalised)
        pkg = obj.get('package', '')
        if pkg:
            for c in _normalise(pkg):
                bag.add(c)

        # 2. displayName from olm.csv.metadata
        for prop in obj.get('properties', []):
            if prop.get('type') == 'olm.csv.metadata':
                dn = prop.get('value', {}).get('displayName', '')
                if dn:
                    for c in _normalise(dn):
                        bag.add(c)
                break

    return ns_candidates


def build_map(catalog_files: list[str]) -> dict[str, list[str]]:
    """Merge candidates from all catalogs and return the final map."""
    merged: dict[str, set[str]] = {}

    for path in catalog_files:
        print(f"  Parsing {os.path.basename(path)} …")
        partial = _parse_catalog(path)
        for ns, candidates in partial.items():
            merged.setdefault(ns, set()).update(candidates)

    # Sort for deterministic output
    return {ns: sorted(candidates) for ns, candidates in sorted(merged.items())}


def main():
    default_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'catalogs')
    catalog_files = sys.argv[1:] or sorted(glob.glob(os.path.join(default_dir, 'catalog*.json')))
    if not catalog_files:
        print(f"No catalog*.json files found in {default_dir}. Pass paths as arguments or place catalogs there.")
        sys.exit(1)

    print(f"Processing {len(catalog_files)} catalog file(s):")
    ns_map = build_map(catalog_files)

    os.makedirs('data', exist_ok=True)
    out_path = os.path.join('data', 'ns_vex_prefixes.json')
    with open(out_path, 'w') as fh:
        json.dump(ns_map, fh, indent=2)

    print(f"\nWrote {len(ns_map)} namespace entries to {out_path}")
    print("\nSample (first 10):")
    for ns, prefixes in list(ns_map.items())[:10]:
        print(f"  {ns:45s} → {prefixes[:3]}")


if __name__ == '__main__':
    main()
