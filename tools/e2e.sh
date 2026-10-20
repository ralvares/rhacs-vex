#!/bin/bash
# End to end on one image: syft SBOM, grype + trivy reports, vextriage triage in all three
# modes, OpenVEX (free scan and per scanner), the scanners re-run with --vex, and the diff.
#
#   tools/e2e.sh NAME IMAGE-REF [OUTDIR=data/scans]
#
# Registry credentials: syft, grype and trivy read $DOCKER_CONFIG/config.json (or
# ~/.docker/config.json); an OpenShift pull secret is that file's format.
set -u
n=$1; ref=$2; d=${3:-data/scans}/$n; mkdir -p "$d"
here=$(cd "$(dirname "$0")" && pwd)
if [ ! -s "$d/sbom.syft.json" ]; then
  syft "$ref" -o syft-json="$d/sbom.syft.json" -q || { echo "$n: syft failed"; exit 1; }
fi
pin=$(python3 -c "
import json; s=json.load(open('$d/sbom.syft.json'))['source']['metadata']
rd=[r for r in s.get('repoDigests') or [] if '@sha256:' in r]
print(rd[0] if rd else '$ref')")
echo "$pin" > "$d/ref"
grype "sbom:$d/sbom.syft.json" -o json -q > "$d/grype.raw.json"
trivy image -q -f json "$pin" > "$d/trivy.raw.json" 2> "$d/trivy.raw.err"
vextriage scan --sbom "$d/sbom.syft.json" --json "$d/free.json" > "$d/free.txt" 2>/dev/null
vextriage scan --sbom "$d/sbom.syft.json" --grype "$d/grype.raw.json" --json "$d/grype-triage.json" \
  --openvex "$d/xg.openvex.json" --all > "$d/grype.txt" 2>/dev/null
vextriage scan --sbom "$d/sbom.syft.json" --trivy "$d/trivy.raw.json" --json "$d/trivy-triage.json" \
  --openvex "$d/xt.openvex.json" --all > "$d/trivy.txt" 2>/dev/null
vextriage openvex --sbom "$d/sbom.syft.json" -o "$d/x.openvex.json" 2>/dev/null
grype "sbom:$d/sbom.syft.json" --vex "$d/x.openvex.json" -o json -q > "$d/grype.vex.json"
grype "sbom:$d/sbom.syft.json" --vex "$d/xg.openvex.json" -o json -q > "$d/grype.vexg.json"
trivy image -q -f json --vex "$d/x.openvex.json" "$pin" > "$d/trivy.vex.json" 2>/dev/null
trivy image -q -f json --vex "$d/xt.openvex.json" "$pin" > "$d/trivy.vext.json" 2>/dev/null
python3 "$here/e2e_compare.py" "$d"
