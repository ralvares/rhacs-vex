#!/usr/bin/env bash
# retriage_all.sh — Re-run audit on all OCP releases from cached data.
#
# ZERO network calls. Reads directly from:
#   data/scans/  → cached RHACS scan JSONs
#   data/vex/    → cached Red Hat VEX files
#   data/sbom/   → cached SBOMs
#
# Usage:
#   bash retriage_all.sh                    # all manifests
#   bash retriage_all.sh 4.21.13.txt        # single version
#   WORKERS=5 bash retriage_all.sh          # limit parallelism

set -euo pipefail

WORKERS="${WORKERS:-10}"
REPORT_DIR="data/reports"

mkdir -p "$REPORT_DIR"

# Parse args
MANIFESTS=()
for arg in "$@"; do
    case "$arg" in
        *.txt) MANIFESTS+=("$arg") ;;
    esac
done

# Default: all manifest files
if [ ${#MANIFESTS[@]} -eq 0 ]; then
    mapfile -t MANIFESTS < <(ls 4.*.txt 2>/dev/null | sort -V)
fi

if [ ${#MANIFESTS[@]} -eq 0 ]; then
    echo "ERROR: No manifest files (4.*.txt) found in current directory."
    exit 1
fi

TOTAL=${#MANIFESTS[@]}

echo "=== Offline Re-triage: $TOTAL OCP releases ==="
echo "    No network calls — cached scans/VEX/SBOMs only."
echo ""

python3 - "${MANIFESTS[@]}" <<'PYEOF'
import sys, os, re, json, time

sys.path.insert(0, '.')
import triage
import pandas as pd

manifests  = sys.argv[1:]
report_dir = 'data/reports'
grand_t0   = time.time()

def log(msg):
    print(msg, flush=True)

def retriage_one(manifest_file):
    ver = os.path.splitext(os.path.basename(manifest_file))[0]
    out = os.path.join(report_dir, f'ocp-{ver}.csv')

    # Parse manifest
    images = []
    ocp_ver = None
    with open(manifest_file) as f:
        for line in f:
            nm = re.match(r'^Name:\s+(.+)', line)
            if nm and ocp_ver is None:
                ocp_ver = nm.group(1).strip()
                continue
            m = re.match(r'^(\S+)\s+(\S+@sha256:[a-f0-9]+)', line.strip())
            if m:
                images.append((m.group(1), m.group(2)))

    if not images:
        return ver, 0, 0, 0, 'no images in manifest'

    minor_ver = '.'.join((ocp_ver or ver).split('.')[:2])
    all_results = []
    scanned = 0
    skipped = 0
    total_findings = 0
    total_imgs = len(images)

    for idx, (comp_name, image_ref) in enumerate(images, 1):
        # Load cached scan JSON — no RHACS call
        cache_path = triage._scan_cache_path('', image_ref)
        if not os.path.exists(cache_path):
            skipped += 1
            if idx % 50 == 0 or idx == total_imgs:
                log(f'    [{idx}/{total_imgs}] {scanned} scanned, {skipped} skipped...')
            continue

        try:
            with open(cache_path) as fh:
                image_data = json.load(fh)
        except Exception:
            skipped += 1
            continue

        labels  = (image_data.get('metadata') or {}).get('v1', {}).get('labels') or {}
        img_ctx = triage.parse_context_from_labels(labels, image_ref) if labels \
                  else triage.parse_image_ref(image_ref)
        os_info = (image_data.get('scan') or {}).get('operatingSystem', '')

        # Enforce OCP release context
        img_ctx.workload_type = 'ocp'
        img_ctx.ocp_ver = minor_ver
        os_rhel = re.search(r'(?:rhel|coreos):(\d+)', os_info or '')
        if os_rhel:
            img_ctx.rhel_ver = os_rhel.group(1)
        elif comp_name:
            cn_rhel = re.search(r'(?:rhel-[^-]+-|rhel-)(\d+)$', comp_name)
            if cn_rhel:
                img_ctx.rhel_ver = cn_rhel.group(1)
        img_ctx.display_name = f'OpenShift {ocp_ver or ver}'
        img_ctx.extra_prefixes = []
        img_ctx.ocp_component = comp_name

        # Build SBOM source map from cached SBOM (optional)
        if hasattr(triage, '_sbom_cache_path'):
            sbom_path = triage._sbom_cache_path(image_ref)
            if os.path.exists(sbom_path):
                try:
                    with open(sbom_path) as fh:
                        sbom = json.load(fh)
                    img_ctx.sbom_src_map = triage._build_sbom_src_map(sbom)
                except Exception:
                    pass

        img_df = triage.rhacs_to_df(image_data)
        if img_df.empty:
            scanned += 1
            if idx % 50 == 0 or idx == total_imgs:
                log(f'    [{idx}/{total_imgs}] {scanned} scanned, {skipped} skipped...')
            continue

        # Run audit (VEX files loaded from disk, no download)
        img_df['RHACS_SEVERITY'] = img_df['SEVERITY'].apply(
            lambda s: triage._RHACS_SEVERITY_MAP.get(str(s).strip().upper(), 'Unknown')
        )
        img_df[['AUDIT_RESULT', 'VEX_FIX_VER', 'JUSTIFICATION', 'SEVERITY']] = img_df.apply(
            lambda row: list(triage.audit_row_detailed(row, img_ctx)), axis=1, result_type='expand'
        )
        img_df['VEX_PRODUCT'] = img_df.apply(
            lambda row: triage._vex_product_for_row(row, img_ctx), axis=1)
        img_df['SEVERITY_MISMATCH'] = (
            (img_df['RHACS_SEVERITY'] != 'Unknown') &
            (img_df['SEVERITY'] != img_df['RHACS_SEVERITY'])
        )
        img_df['OCP_COMPONENT'] = comp_name
        img_df['IMAGE'] = image_ref
        result_df = triage._sort_and_filter_df(img_df, False)
        all_results.append(result_df)
        total_findings += len(result_df)
        scanned += 1

        if idx % 50 == 0 or idx == total_imgs:
            log(f'    [{idx}/{total_imgs}] {scanned} scanned, {skipped} skipped, {total_findings} findings')

    if all_results:
        combined = pd.concat(all_results, ignore_index=True)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        combined.to_csv(out, index=False)
        pos = (combined['AUDIT_RESULT'].str.contains('POSITIVE') & ~combined['AUDIT_RESULT'].str.contains('FALSE')).sum()
        fp  = combined['AUDIT_RESULT'].str.contains('FALSE').sum()
        return ver, scanned, skipped, len(combined), f'{pos} positive, {fp} false positive'
    else:
        return ver, scanned, skipped, 0, 'no findings'


for i, mf in enumerate(manifests, 1):
    pct  = int(100 * i / len(manifests))
    ver0 = os.path.splitext(os.path.basename(mf))[0]
    log(f'[{i}/{len(manifests)}] ({pct}%) {ver0}')
    t0 = time.time()
    ver, ok, skip, nf, msg = retriage_one(mf)
    elapsed = time.time() - t0
    log(f'  ✅ {ok} images, {skip} skipped, {nf} findings — {msg} ({elapsed:.1f}s)')
    log('')

total_elapsed = time.time() - grand_t0
log(f'=== Done: {len(manifests)} versions in {total_elapsed:.0f}s ({total_elapsed/60:.1f} min) ===')

# Build per-version parquets + manifest + cve-index
log('')
log('=== Building parquet files ===')
import subprocess
subprocess.run([sys.executable, 'build_parquet.py'], check=False)
log('Done.')
PYEOF
