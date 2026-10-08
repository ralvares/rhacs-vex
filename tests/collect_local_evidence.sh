#!/usr/bin/env bash
# Run on a machine with registry access; produces evidence.tar.gz to upload.
#
#   tests/collect_local_evidence.sh <image@sha256:…> [<image@sha256:…> …]
#
# Needs: syft, trivy (grype optional), registry login for registry.redhat.io.
# Run from the repo root after `pip install -e .`.  Collects only small files:
# SBOMs, scanner reports with and without the generated OpenVEX, the OpenVEX
# documents, and the legacy-vs-new engine diff on your cached RHACS scans.
set -uo pipefail

# Packages only: file digests / executable analysis are not needed (rpm file
# ownership comes from the rpm db) and time out on big images.
export SYFT_FILE_METADATA_SELECTION=none SYFT_FILE_METADATA_DIGESTS="" \
       SYFT_FILE_EXECUTABLE_GLOBS="" SYFT_CHECK_FOR_APP_UPDATE=false
[ $# -ge 1 ] || { echo "usage: $0 <image@sha256:…> …" >&2; exit 2; }

OUT=evidence; rm -rf "$OUT"; mkdir -p "$OUT"
{ syft version; trivy --version; grype version 2>/dev/null || true; python3 --version; git rev-parse HEAD; } \
  > "$OUT/versions.txt" 2>&1

echo "== sync (Red Hat VEX + OSV + index)"
vextriage sync > "$OUT/sync.log" 2>&1 || { echo "sync failed — see $OUT/sync.log"; tail -5 "$OUT/sync.log"; }
tail -5 "$OUT/sync.log"

for ref in "$@"; do
  name=$(echo "$ref" | tr '/:@' '___')
  d="$OUT/$name"; mkdir -p "$d"
  echo "== $ref"
  if ! syft "registry:$ref" --platform linux/amd64 -o "syft-json=$d/sbom.syft.json" 2> "$d/syft.log"; then
    echo "   syft failed, retrying once (see $d/syft.log)"
    syft "registry:$ref" --platform linux/amd64 -o "syft-json=$d/sbom.syft.json" 2>> "$d/syft.log" \
      || { echo "   syft failed twice — skipping $ref"; continue; }
  fi
  syft convert "$d/sbom.syft.json" -o "cyclonedx-json=$d/sbom.cdx.json" 2>> "$d/syft.log" || true
  VEX_SKIP_SYNC=1 vextriage openvex "$d/sbom.syft.json" --image "$ref" -o "$d/openvex.json" > "$d/openvex.log" 2>&1
  trivy image "$ref" --platform linux/amd64 -q -f json -o "$d/trivy.json" 2> "$d/trivy.log" || echo "   trivy failed (see $d/trivy.log)"
  trivy image "$ref" --platform linux/amd64 -q -f json --vex "$d/openvex.json" -o "$d/trivy.vex.json" 2>> "$d/trivy.log" || true
  if command -v grype >/dev/null; then
    grype "sbom:$d/sbom.syft.json" --by-cve -o json > "$d/grype.json" 2> "$d/grype.log" || true
    grype "sbom:$d/sbom.syft.json" --by-cve -o json --vex "$d/openvex.json" > "$d/grype.vex.json" 2>> "$d/grype.log" || true
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
