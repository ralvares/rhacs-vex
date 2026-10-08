#!/usr/bin/env bash
# Run on a machine with registry access; produces evidence.tar.gz to upload.
#
#   tests/collect_local_evidence.sh <image@sha256:…> [<image@sha256:…> …]
#
# Needs: syft, grype, registry login for registry.redhat.io (for syft).
# Run from the repo root after `pip install -e .`.  Collects only small files:
# SBOMs, grype reports with and without the generated OpenVEX, the OpenVEX
# documents, and the legacy-vs-new engine diff on your cached RHACS scans.
set -uo pipefail

# Packages only: file digests / executable analysis are not needed (rpm file
# ownership comes from the rpm db) and time out on big images.
export SYFT_FILE_METADATA_SELECTION=none SYFT_FILE_METADATA_DIGESTS="" \
       SYFT_FILE_EXECUTABLE_GLOBS="" SYFT_CHECK_FOR_APP_UPDATE=false
[ $# -ge 1 ] || { echo "usage: $0 <image@sha256:…> …" >&2; exit 2; }
command -v grype >/dev/null || { echo "grype is required (brew install grype)" >&2; exit 2; }

# Use THIS checkout, not an older installed copy of the package.
VEXTRIAGE_BIN=$(command -v vextriage || true)
python3 -c "import rhacs_vex, os, sys; sys.exit(0 if os.path.realpath(rhacs_vex.__file__).startswith(os.path.realpath('src')) else 1)" \
  || { echo "vextriage is not this checkout — run: pip install -e .  (from the repo root)" >&2; exit 2; }

OUT=evidence; rm -rf "$OUT"; mkdir -p "$OUT"
{ syft version; grype version; python3 --version; git rev-parse HEAD; echo "vextriage: $VEXTRIAGE_BIN"; } \
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
  VEX_SKIP_SYNC=1 vextriage openvex "$d/sbom.syft.json" --image "$ref" -o "$d/openvex.json" > "$d/openvex.log" 2>&1
  tail -1 "$d/openvex.log"
  # grype reads the syft SBOM directly — no image pull.
  grype "sbom:$d/sbom.syft.json" --by-cve -o json > "$d/grype.json" 2> "$d/grype.log" \
    || echo "   grype failed (see $d/grype.log)"
  grype "sbom:$d/sbom.syft.json" --by-cve -o json --vex "$d/openvex.json" > "$d/grype.vex.json" 2>> "$d/grype.log" || true
  VEX_SKIP_SYNC=1 vextriage check "$d/sbom.syft.json" --image "$ref" --hub "" --quiet > "$d/check.log" 2>&1 || true
  tail -1 "$d/check.log"
done

if [ -n "$(find data/scans -maxdepth 1 -name '*.json' -print -quit 2>/dev/null)" ]; then
  echo "== legacy vs new engine on cached RHACS scans"
  python3 tests/diff_engines_corpus.py --show 50 > "$OUT/diff_corpus.txt" 2>&1 || true
  tail -1 "$OUT/diff_corpus.txt"
fi
[ -f data/baseline.json ] && { python3 tests/check_baseline.py > "$OUT/check_baseline.txt" 2>&1 || true; }

COPYFILE_DISABLE=1 tar czf evidence.tar.gz "$OUT"
ls -lh evidence.tar.gz
echo "upload evidence.tar.gz"
