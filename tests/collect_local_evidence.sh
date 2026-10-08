#!/usr/bin/env bash
# Run on a machine with registry access; produces evidence.tar.gz to upload.
#
#   tests/collect_local_evidence.sh <image@sha256:…> [<image@sha256:…> …]
#
# Needs: syft, trivy (grype optional), registry login for registry.redhat.io.
# Run from the repo root after `pip install -e .`.  Collects only small files:
# SBOMs, scanner reports with and without the generated OpenVEX, the OpenVEX
# documents, and the legacy-vs-new engine diff on your cached RHACS scans.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 <image@sha256:…> …" >&2; exit 2; }

OUT=evidence; rm -rf "$OUT"; mkdir -p "$OUT"
{ syft version; trivy --version; grype version 2>/dev/null || true; python3 --version; git rev-parse HEAD; } \
  > "$OUT/versions.txt" 2>&1

echo "== sync (Red Hat VEX + OSV + index)"
vextriage sync 2>&1 | tail -20 > "$OUT/sync.log"

for ref in "$@"; do
  name=$(echo "$ref" | tr '/:@' '___')
  d="$OUT/$name"; mkdir -p "$d"
  echo "== $ref"
  syft "registry:$ref" --platform linux/amd64 -o "syft-json=$d/sbom.syft.json" -o "cyclonedx-json=$d/sbom.cdx.json"
  VEX_SKIP_SYNC=1 vextriage openvex "$d/sbom.syft.json" --image "$ref" -o "$d/openvex.json" > "$d/openvex.log" 2>&1
  trivy image "$ref" --platform linux/amd64 -q -f json -o "$d/trivy.json"
  trivy image "$ref" --platform linux/amd64 -q -f json --vex "$d/openvex.json" -o "$d/trivy.vex.json"
  if command -v grype >/dev/null; then
    grype "sbom:$d/sbom.syft.json" --by-cve -o json > "$d/grype.json"
    grype "sbom:$d/sbom.syft.json" --by-cve -o json --vex "$d/openvex.json" > "$d/grype.vex.json"
  fi
  VEX_SKIP_SYNC=1 vextriage check "$ref" --hub "" --sbom "$d/sbom.syft.json" --quiet > "$d/check.log" 2>&1 || true
done

if ls data/scans/*.json >/dev/null 2>&1; then
  echo "== legacy vs new engine on cached RHACS scans"
  python3 tests/diff_engines_corpus.py --show 50 > "$OUT/diff_corpus.txt" 2>&1 || true
fi
[ -f data/baseline.json ] && { python3 tests/check_baseline.py > "$OUT/check_baseline.txt" 2>&1 || true; }

tar czf evidence.tar.gz "$OUT"
ls -lh evidence.tar.gz
echo "upload evidence.tar.gz"
