#!/usr/bin/env bash
#
# rhacs-metrics-collect.sh - scrape RHACS custom Prometheus metrics into a
# SQLite ledger, reconstructing the closed-vulnerability history that RHACS
# itself does not keep.
#
# Source this file from your shell (or from ~/.bashrc / ~/.zshrc):
#
#   source examples/rhacs-metrics-collect.sh
#
# Required environment:
#
#   export ROX_ENDPOINT=central.example.com:443
#   export ROX_API_TOKEN=<token>       # read access: Administration (metrics)
#
# Optional:
#
#   export ROX_CA_FILE=/path/ca.pem    # verify TLS (default: -k)
#   export RHACS_METRICS_DB=path.db    # SQLite file (default: rhacs-metrics.db)
#   export RHACS_METRICS_ARCHIVE=dir   # keep raw scrapes here (replay/audit)
#
# Commands:
#
#   rhacs-metrics-init      create tables and report views (idempotent)
#   rhacs-metrics-collect   scrape /metrics, refresh facts_* snapshots, upsert
#                           ledgers, mark closed/retired. Run from cron, e.g.:
#                           0 * * * * bash -c 'source .../rhacs-metrics-collect.sh && rhacs-metrics-collect'
#
# The ONLY data source is Central's /metrics endpoint. Because metrics carry
# no dates, findings already open at the very first collect have unknown true
# age (their first_seen = pipeline start); MTTR views/reports exclude that
# bootstrap cohort, so MTTR is computed only over findings whose discovery
# the pipeline actually observed.
#
# Requires the full-label metric descriptors in Central config
# (privateConfig.metrics): "finding" + "severity" descriptors on
# imageVulnerabilities and nodeVulnerabilities, "finding" +
# "namespace_severity" on policyViolations. Reports: rhacs-metrics-report.sh.
#
# Dependencies: curl, python3, sqlite3

# Resolve the directory this file lives in, at source time (not inside a
# function): bash exposes BASH_SOURCE; zsh sets $0 to the sourced file.
_ROXM_DIR=$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)

_roxm_db() {
    echo "${RHACS_METRICS_DB:-rhacs-metrics.db}"
}

_roxm_curl() {
    local path="$1" tls=(-k)
    [ -n "${ROX_CA_FILE:-}" ] && tls=(--cacert "$ROX_CA_FILE")
    if [ -z "${ROX_ENDPOINT:-}" ] || [ -z "${ROX_API_TOKEN:-}" ]; then
        echo "error: ROX_ENDPOINT and ROX_API_TOKEN must be set" >&2
        return 1
    fi
    /usr/bin/curl -sS --max-time 600 --retry 2 --retry-all-errors "${tls[@]}" \
        -H "Authorization: Bearer $ROX_API_TOKEN" \
        "https://${ROX_ENDPOINT}${path}"
}

rhacs-metrics-init() {
    sqlite3 "$(_roxm_db)" < "$_ROXM_DIR/rhacs-metrics-schema.sql" &&
        echo "schema applied to $(_roxm_db)"
}

# Parse Prometheus exposition text ($2) into TSV files under $1 for .import.
# Handles escaped quotes/backslashes and commas inside label values.
# Prints "<image> <node> <violation>" finding counts on stdout.
_roxm_parse() {
    python3 - "$1" "$2" <<'PYEOF'
import re, sys

outdir, scrape = sys.argv[1], sys.argv[2]
line_re = re.compile(r'^(\w+)\{(.*)\}\s+([0-9.eE+-]+)$')
lab_re = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
unesc = lambda s: s.replace(r'\"', '"').replace(r'\n', ' ').replace('\\\\', '\\')

files = {
    "img": open(f"{outdir}/img.tsv", "w"),
    "node": open(f"{outdir}/node.tsv", "w"),
    "viol": open(f"{outdir}/viol.tsv", "w"),
    "sev": open(f"{outdir}/sev.tsv", "w"),
}
counts = dict.fromkeys(files, 0)

def row(f, fields):
    files[f].write("\t".join(x.replace("\t", " ") for x in fields) + "\n")
    counts[f] += 1

for line in open(scrape):
    m = line_re.match(line.strip())
    if not m:
        continue
    name, raw, value = m.groups()
    lab = {k: unesc(v) for k, v in lab_re.findall(raw)}
    g = lab.get
    if name == "rox_central_image_vuln_finding":
        row("img", [lab["CVE"], g("CVSS", ""), lab["Cluster"], lab["Namespace"],
                    lab["Deployment"], g("Type", ""), g("IsActive", "true"),
                    g("IsPlatformWorkload", "false"), g("ImageID", ""),
                    lab["ImageRegistry"], lab["ImageRemote"], lab["ImageTag"],
                    lab["Component"], lab["ComponentVersion"],
                    g("OperatingSystem", ""), lab["Severity"], lab["IsFixable"],
                    g("EPSSProbability", ""), g("EPSSPercentile", "")])
    elif name == "rox_central_node_vuln_finding":
        row("node", [lab["Cluster"], lab["Node"], g("Kernel", ""),
                     g("OSImage", ""), g("OperatingSystem", ""),
                     lab["Component"], lab["ComponentVersion"], lab["CVE"],
                     g("CVSS", ""), lab["Severity"], lab["IsFixable"],
                     g("IsSnoozed", "false"), g("EPSSProbability", ""),
                     g("EPSSPercentile", "")])
    elif name == "rox_central_policy_violation_finding":
        row("viol", [lab["Cluster"], lab["Namespace"], g("Deployment", ""),
                     g("Resource", ""), lab["Policy"], g("Categories", ""),
                     lab["Severity"], g("Action", ""), g("Stage", ""),
                     g("State", ""), g("Entity", ""), g("EntityName", ""),
                     g("Type", ""), g("IsDeploymentActive", "true"),
                     g("IsPlatformComponent", "false"),
                     str(int(float(value)))])
    elif name == "rox_central_image_vuln_severity":
        row("sev", [lab["Cluster"], lab["Namespace"], lab["Severity"],
                    lab["IsFixable"], g("IsPlatformWorkload", "false"),
                    str(int(float(value)))])

for f in files.values():
    f.close()
print(f"parsed: {counts['img']} image findings, {counts['node']} node findings, "
      f"{counts['viol']} violations, {counts['sev']} severity rows", file=sys.stderr)
print(f"{counts['img']} {counts['node']} {counts['viol']}")
PYEOF
}

rhacs-metrics-collect() {
    local tmpdir ts nums
    tmpdir=$(mktemp -d) || return 1
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    _roxm_curl "/metrics" > "$tmpdir/scrape.txt" || { rm -rf "$tmpdir"; return 1; }
    nums=$(_roxm_parse "$tmpdir" "$tmpdir/scrape.txt") || { rm -rf "$tmpdir"; return 1; }

    local nimg nnode nviol rest
    nimg=${nums%% *}; rest=${nums#* }; nnode=${rest%% *}; nviol=${rest##* }
    # Empty scrape usually means gathering just (re)started - closing the whole
    # ledger on it would be catastrophic, so refuse.
    if [ "$nimg" -eq 0 ]; then
        echo "error: 0 image findings in scrape; refusing to update ledger" >&2
        echo "       (first scrape after a config change is empty - retry in a minute)" >&2
        rm -rf "$tmpdir"
        return 1
    fi

    if [ -n "${RHACS_METRICS_ARCHIVE:-}" ]; then
        mkdir -p "$RHACS_METRICS_ARCHIVE" &&
            gzip -c "$tmpdir/scrape.txt" > "$RHACS_METRICS_ARCHIVE/scrape-$ts.txt.gz"
    fi

    sqlite3 "$(_roxm_db)" <<SQL
.bail on
CREATE TEMP TABLE stage_img (cve TEXT, cvss TEXT, cluster TEXT, namespace TEXT,
    deployment TEXT, deployment_type TEXT, is_active TEXT,
    platform_workload TEXT, image_id TEXT, image_registry TEXT,
    image_remote TEXT, image_tag TEXT, component TEXT,
    component_version TEXT, operating_system TEXT, severity TEXT,
    fixable TEXT, epss_probability TEXT, epss_percentile TEXT);
CREATE TEMP TABLE stage_node (cluster TEXT, node TEXT, kernel TEXT,
    os_image TEXT, operating_system TEXT, component TEXT,
    component_version TEXT, cve TEXT, cvss TEXT, severity TEXT, fixable TEXT,
    snoozed TEXT, epss_probability TEXT, epss_percentile TEXT);
CREATE TEMP TABLE stage_viol (cluster TEXT, namespace TEXT, deployment TEXT,
    resource TEXT, policy TEXT, categories TEXT, severity TEXT, action TEXT,
    stage TEXT, state TEXT, entity TEXT, entity_name TEXT,
    violation_type TEXT, is_deployment_active TEXT,
    is_platform_component TEXT, violation_count INTEGER);
CREATE TEMP TABLE stage_sev (cluster TEXT, namespace TEXT, severity TEXT,
    fixable TEXT, platform_workload TEXT, findings INTEGER);
.mode tabs
.import $tmpdir/img.tsv stage_img
.import $tmpdir/node.tsv stage_node
.import $tmpdir/viol.tsv stage_viol
.import $tmpdir/sev.tsv stage_sev

BEGIN;

-- ---------------- facts: full-width snapshot of the latest scrape
DELETE FROM facts_image;
INSERT INTO facts_image
SELECT '$ts', cve, nullif(cvss,''), cluster, namespace, deployment,
       deployment_type, is_active, platform_workload, image_id,
       image_registry, image_remote, image_tag, component, component_version,
       operating_system, severity, fixable, nullif(epss_probability,''),
       nullif(epss_percentile,'')
FROM stage_img;

DELETE FROM facts_node;
INSERT INTO facts_node
SELECT '$ts', cluster, node, kernel, os_image, operating_system, component,
       component_version, cve, nullif(cvss,''), severity, fixable, snoozed,
       nullif(epss_probability,''), nullif(epss_percentile,'')
FROM stage_node;

DELETE FROM facts_violation;
INSERT INTO facts_violation
SELECT '$ts', cluster, namespace, deployment, resource, policy, categories,
       severity, action, stage, state, entity, entity_name, violation_type,
       is_deployment_active, is_platform_component, violation_count
FROM stage_viol;

-- ---------------- image-level ledger (digest-agnostic key)
INSERT INTO vuln_findings (cve, image_registry, image_remote, image_tag,
    image_id, severity, fixable, platform_workload, cvss, epss_probability,
    operating_system, first_seen, last_seen)
SELECT cve, image_registry, image_remote, image_tag,
    max(image_id), max(severity), max(fixable), max(platform_workload),
    max(CAST(nullif(cvss,'') AS REAL)),
    max(CAST(nullif(epss_probability,'') AS REAL)),
    max(operating_system), '$ts', '$ts'
FROM stage_img
GROUP BY cve, image_registry, image_remote, image_tag
ON CONFLICT (cve, image_registry, image_remote, image_tag) DO UPDATE SET
    last_seen = excluded.last_seen,
    image_id = excluded.image_id,
    severity = excluded.severity,
    fixable = excluded.fixable,
    platform_workload = excluded.platform_workload,
    cvss = excluded.cvss,
    epss_probability = excluded.epss_probability,
    operating_system = excluded.operating_system,
    reopen_count = reopen_count
        + (closed_at IS NOT NULL OR retired_at IS NOT NULL),
    closed_at = NULL,
    closed_reason = NULL,
    retired_at = NULL;

UPDATE vuln_findings AS f
SET closed_at = '$ts',
    closed_reason = CASE
        WHEN EXISTS (SELECT 1 FROM stage_img s
            WHERE s.image_registry = f.image_registry
              AND s.image_remote = f.image_remote
              AND s.image_tag = f.image_tag
              AND s.image_id = f.image_id)
            THEN 'feed-change'      -- same digest still running, CVE no longer reported
        WHEN EXISTS (SELECT 1 FROM stage_img s
            WHERE s.image_registry = f.image_registry
              AND s.image_remote = f.image_remote
              AND s.image_tag = f.image_tag)
            THEN 'image-updated'    -- same tag, new digest: rebuild/rollout
        ELSE 'tag-replaced'         -- tag gone, repo still present
    END
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.cve = f.cve AND s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote AND s.image_tag = f.image_tag)
  AND EXISTS (SELECT 1 FROM stage_img s
      WHERE s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote);

UPDATE vuln_findings AS f SET retired_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote);

-- ---------------- digest history
INSERT INTO image_history (image_registry, image_remote, image_tag, image_id,
    first_seen, last_seen)
SELECT DISTINCT image_registry, image_remote, image_tag, image_id, '$ts', '$ts'
FROM stage_img WHERE image_id != ''
ON CONFLICT (image_registry, image_remote, image_tag, image_id) DO UPDATE SET
    last_seen = excluded.last_seen,
    gone_at = NULL;

UPDATE image_history AS h SET gone_at = '$ts'
WHERE h.gone_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.image_registry = h.image_registry
        AND s.image_remote = h.image_remote
        AND s.image_tag = h.image_tag
        AND s.image_id = h.image_id);

-- ---------------- deployment-level ledger
INSERT INTO deployment_vuln_findings (cluster, namespace, deployment, cve,
    severity, fixable, cvss, epss_probability, first_seen, last_seen)
SELECT cluster, namespace, deployment, cve, max(severity), max(fixable),
    max(CAST(nullif(cvss,'') AS REAL)),
    max(CAST(nullif(epss_probability,'') AS REAL)), '$ts', '$ts'
FROM stage_img
GROUP BY cluster, namespace, deployment, cve
ON CONFLICT (cluster, namespace, deployment, cve) DO UPDATE SET
    last_seen = excluded.last_seen,
    severity = excluded.severity,
    fixable = excluded.fixable,
    cvss = excluded.cvss,
    epss_probability = excluded.epss_probability,
    reopen_count = reopen_count
        + (closed_at IS NOT NULL OR retired_at IS NOT NULL),
    closed_at = NULL,
    retired_at = NULL;

UPDATE deployment_vuln_findings AS f SET closed_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment AND s.cve = f.cve)
  AND EXISTS (SELECT 1 FROM stage_img s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment);

UPDATE deployment_vuln_findings AS f SET retired_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment);

-- ---------------- component-level ledger
INSERT INTO component_vuln_findings (cve, component, component_version,
    image_registry, image_remote, image_tag, severity, fixable,
    operating_system, first_seen, last_seen)
SELECT cve, component, component_version, image_registry, image_remote,
    image_tag, max(severity), max(fixable), max(operating_system), '$ts', '$ts'
FROM stage_img
GROUP BY cve, component, component_version, image_registry, image_remote, image_tag
ON CONFLICT (cve, component, component_version, image_registry, image_remote,
             image_tag) DO UPDATE SET
    last_seen = excluded.last_seen,
    severity = excluded.severity,
    fixable = excluded.fixable,
    operating_system = excluded.operating_system,
    reopen_count = reopen_count
        + (closed_at IS NOT NULL OR retired_at IS NOT NULL),
    closed_at = NULL,
    retired_at = NULL;

UPDATE component_vuln_findings AS f SET closed_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.cve = f.cve AND s.component = f.component
        AND s.component_version = f.component_version
        AND s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote AND s.image_tag = f.image_tag)
  AND EXISTS (SELECT 1 FROM stage_img s
      WHERE s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote);

UPDATE component_vuln_findings AS f SET retired_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_img s
      WHERE s.image_registry = f.image_registry
        AND s.image_remote = f.image_remote);

-- ---------------- node ledger (per component)
INSERT INTO node_vuln_findings (cluster, node, cve, component,
    component_version, kernel, os_image, severity, fixable, snoozed, cvss,
    first_seen, last_seen)
SELECT cluster, node, cve, component, max(component_version), max(kernel),
    max(os_image), max(severity), max(fixable), max(snoozed),
    max(CAST(nullif(cvss,'') AS REAL)), '$ts', '$ts'
FROM stage_node
GROUP BY cluster, node, cve, component
ON CONFLICT (cluster, node, cve, component) DO UPDATE SET
    last_seen = excluded.last_seen,
    component_version = excluded.component_version,
    kernel = excluded.kernel,
    os_image = excluded.os_image,
    severity = excluded.severity,
    fixable = excluded.fixable,
    snoozed = excluded.snoozed,
    cvss = excluded.cvss,
    reopen_count = reopen_count
        + (closed_at IS NOT NULL OR retired_at IS NOT NULL),
    closed_at = NULL,
    retired_at = NULL;

UPDATE node_vuln_findings AS f SET closed_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_node s
      WHERE s.cluster = f.cluster AND s.node = f.node AND s.cve = f.cve
        AND s.component = f.component)
  AND EXISTS (SELECT 1 FROM stage_node s
      WHERE s.cluster = f.cluster AND s.node = f.node);

UPDATE node_vuln_findings AS f SET retired_at = '$ts'
WHERE f.closed_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_node s
      WHERE s.cluster = f.cluster AND s.node = f.node);

-- ---------------- violations ledger
INSERT INTO violation_findings (cluster, namespace, deployment, resource,
    policy, stage, severity, categories, action, state, entity, entity_name,
    violation_type, violation_count, first_seen, last_seen)
SELECT cluster, namespace, deployment, resource, policy, stage,
    max(severity), max(categories), max(action), max(state), max(entity),
    max(entity_name), max(violation_type), sum(violation_count), '$ts', '$ts'
FROM stage_viol
GROUP BY cluster, namespace, deployment, resource, policy, stage
ON CONFLICT (cluster, namespace, deployment, resource, policy, stage)
DO UPDATE SET
    last_seen = excluded.last_seen,
    severity = excluded.severity,
    categories = excluded.categories,
    action = excluded.action,
    state = excluded.state,
    entity = excluded.entity,
    entity_name = excluded.entity_name,
    violation_type = excluded.violation_type,
    violation_count = excluded.violation_count,
    reopen_count = reopen_count
        + (resolved_at IS NOT NULL OR retired_at IS NOT NULL),
    resolved_at = NULL,
    retired_at = NULL;

UPDATE violation_findings AS f SET resolved_at = '$ts'
WHERE f.resolved_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_viol s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment AND s.resource = f.resource
        AND s.policy = f.policy AND s.stage = f.stage)
  AND EXISTS (SELECT 1 FROM stage_viol s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment);

UPDATE violation_findings AS f SET retired_at = '$ts'
WHERE f.resolved_at IS NULL AND f.retired_at IS NULL
  AND NOT EXISTS (SELECT 1 FROM stage_viol s
      WHERE s.cluster = f.cluster AND s.namespace = f.namespace
        AND s.deployment = f.deployment);

-- ---------------- aggregates + run log
INSERT INTO vuln_severity_counts (taken_at, cluster, namespace, severity,
    fixable, platform_workload, findings)
SELECT '$ts', cluster, namespace, severity, fixable, platform_workload, findings
FROM stage_sev;

INSERT INTO snapshots (taken_at, vuln_series, node_series, violation_series)
VALUES ('$ts', (SELECT count(*) FROM stage_img),
               (SELECT count(*) FROM stage_node),
               (SELECT count(*) FROM stage_viol));

COMMIT;
SQL
    local rc=$?
    rm -rf "$tmpdir"
    [ $rc -eq 0 ] && echo "collected $ts: $nimg image findings, $nnode node findings, $nviol violations"
    return $rc
}
