-- rhacs-metrics-schema.sql - SQLite schema for the RHACS metrics ledger.
--
-- Applied automatically by rhacs-metrics-init (rhacs-metrics-collect.sh).
--
-- Data flows in from rhacs-metrics-collect.sh, which scrapes Central's
-- /metrics endpoint (full-label "finding" descriptors) and upserts here.
-- RHACS itself keeps no history of closed vulnerabilities; this ledger
-- reconstructs it from series appearing/disappearing between scrapes.
--
-- Two layers:
--   facts_*   - full-width snapshot of the LATEST scrape (replaced each run):
--               every label RHACS exposes, for arbitrary "right now" queries.
--   *_findings- lifecycle ledgers (history): first_seen / last_seen /
--               closed_at / retired_at survive across scrapes -> MTTR.
--
-- Timestamps are ISO8601 UTC strings (2026-07-16T12:00:00Z); use julianday()
-- for date math. Booleans are the strings 'true'/'false' as scraped.

-- ------------------------------------------------------------ fact snapshots

CREATE TABLE IF NOT EXISTS facts_image (
    taken_at          TEXT NOT NULL,
    cve               TEXT NOT NULL,
    cvss              REAL,
    cluster           TEXT NOT NULL,
    namespace         TEXT NOT NULL,
    deployment        TEXT NOT NULL,
    deployment_type   TEXT NOT NULL DEFAULT '',
    is_active         TEXT NOT NULL DEFAULT 'true',
    platform_workload TEXT NOT NULL DEFAULT 'false',
    image_id          TEXT NOT NULL DEFAULT '',
    image_registry    TEXT NOT NULL,
    image_remote      TEXT NOT NULL,
    image_tag         TEXT NOT NULL,
    component         TEXT NOT NULL,
    component_version TEXT NOT NULL,
    operating_system  TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    epss_probability  REAL,
    epss_percentile   REAL
);

CREATE TABLE IF NOT EXISTS facts_node (
    taken_at          TEXT NOT NULL,
    cluster           TEXT NOT NULL,
    node              TEXT NOT NULL,
    kernel            TEXT NOT NULL DEFAULT '',
    os_image          TEXT NOT NULL DEFAULT '',
    operating_system  TEXT NOT NULL DEFAULT '',
    component         TEXT NOT NULL,
    component_version TEXT NOT NULL,
    cve               TEXT NOT NULL,
    cvss              REAL,
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    snoozed           TEXT NOT NULL DEFAULT 'false',
    epss_probability  REAL,
    epss_percentile   REAL
);

CREATE TABLE IF NOT EXISTS facts_violation (
    taken_at            TEXT NOT NULL,
    cluster             TEXT NOT NULL,
    namespace           TEXT NOT NULL,
    deployment          TEXT NOT NULL DEFAULT '',
    resource            TEXT NOT NULL DEFAULT '',
    policy              TEXT NOT NULL,
    categories          TEXT NOT NULL DEFAULT '',
    severity            TEXT NOT NULL,
    action              TEXT NOT NULL DEFAULT '',
    stage               TEXT NOT NULL DEFAULT '',
    state               TEXT NOT NULL DEFAULT '',
    entity              TEXT NOT NULL DEFAULT '',
    entity_name         TEXT NOT NULL DEFAULT '',
    violation_type      TEXT NOT NULL DEFAULT '',
    is_deployment_active TEXT NOT NULL DEFAULT 'true',
    is_platform_component TEXT NOT NULL DEFAULT 'false',
    violation_count     INTEGER NOT NULL DEFAULT 0
);

-- ------------------------------------------------------------ ledgers

-- Image CVE lifecycle. Keyed digest-agnostic on purpose: a CVE that survives
-- an image rebuild keeps its row (and its MTTR clock). Digest history lives
-- in image_history; closed_reason says WHY a CVE stopped being reported.
CREATE TABLE IF NOT EXISTS vuln_findings (
    cve               TEXT NOT NULL,
    image_registry    TEXT NOT NULL,
    image_remote      TEXT NOT NULL,
    image_tag         TEXT NOT NULL,
    image_id          TEXT NOT NULL DEFAULT '',  -- latest digest seen with this CVE
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    platform_workload TEXT NOT NULL DEFAULT 'false',
    cvss              REAL,
    epss_probability  REAL,
    operating_system  TEXT NOT NULL DEFAULT '',
    first_seen        TEXT NOT NULL,  -- backdated by rhacs-metrics-seed when possible
    last_seen         TEXT NOT NULL,
    closed_at         TEXT,           -- gone from scrape, image repo still reported
    closed_reason     TEXT,           -- image-updated | tag-replaced | feed-change
    retired_at        TEXT,           -- gone together with its whole image repo
    reopen_count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cve, image_registry, image_remote, image_tag)
);

-- Deployment-level CVE lifecycle: exact join key to violation_findings.
CREATE TABLE IF NOT EXISTS deployment_vuln_findings (
    cluster          TEXT NOT NULL,
    namespace        TEXT NOT NULL,
    deployment       TEXT NOT NULL,
    cve              TEXT NOT NULL,
    severity         TEXT NOT NULL,
    fixable          TEXT NOT NULL,
    cvss             REAL,
    epss_probability REAL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    closed_at        TEXT,           -- CVE gone, deployment still reported
    retired_at       TEXT,           -- deployment itself gone
    reopen_count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster, namespace, deployment, cve)
);

-- Component-level CVE lifecycle: which package/library carries the CVE.
CREATE TABLE IF NOT EXISTS component_vuln_findings (
    cve               TEXT NOT NULL,
    component         TEXT NOT NULL,
    component_version TEXT NOT NULL,
    image_registry    TEXT NOT NULL,
    image_remote      TEXT NOT NULL,
    image_tag         TEXT NOT NULL,
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    operating_system  TEXT NOT NULL DEFAULT '',
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    closed_at         TEXT,
    retired_at        TEXT,
    reopen_count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cve, component, component_version,
                 image_registry, image_remote, image_tag)
);

-- Every digest ever seen per repo:tag. A new image_id on an existing tag is
-- an image rebuild/rollout; gone_at closes the old digest's row.
CREATE TABLE IF NOT EXISTS image_history (
    image_registry TEXT NOT NULL,
    image_remote   TEXT NOT NULL,
    image_tag      TEXT NOT NULL,
    image_id       TEXT NOT NULL,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    gone_at        TEXT,
    PRIMARY KEY (image_registry, image_remote, image_tag, image_id)
);

-- Host/node CVEs (kernel, rpm, ...), per component.
CREATE TABLE IF NOT EXISTS node_vuln_findings (
    cluster           TEXT NOT NULL,
    node              TEXT NOT NULL,
    cve               TEXT NOT NULL,
    component         TEXT NOT NULL DEFAULT '',
    component_version TEXT NOT NULL DEFAULT '',
    kernel            TEXT NOT NULL DEFAULT '',
    os_image          TEXT NOT NULL DEFAULT '',
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    snoozed           TEXT NOT NULL DEFAULT 'false',
    cvss              REAL,
    first_seen        TEXT NOT NULL,
    last_seen         TEXT NOT NULL,
    closed_at         TEXT,           -- CVE gone, node still reported
    retired_at        TEXT,           -- node itself gone
    reopen_count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster, node, cve, component)
);

CREATE TABLE IF NOT EXISTS violation_findings (
    cluster         TEXT NOT NULL,
    namespace       TEXT NOT NULL,
    deployment      TEXT NOT NULL DEFAULT '',
    resource        TEXT NOT NULL DEFAULT '',
    policy          TEXT NOT NULL,
    stage           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    categories      TEXT NOT NULL DEFAULT '',
    action          TEXT NOT NULL DEFAULT '',
    state           TEXT NOT NULL DEFAULT '',
    entity          TEXT NOT NULL DEFAULT '',
    entity_name     TEXT NOT NULL DEFAULT '',
    violation_type  TEXT NOT NULL DEFAULT '',
    violation_count INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    resolved_at     TEXT,             -- violation gone, deployment still reported
    retired_at      TEXT,             -- deployment itself gone
    reopen_count    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (cluster, namespace, deployment, resource, policy, stage)
);

-- One row per collector run: sanity trail + join anchor for trends.
CREATE TABLE IF NOT EXISTS snapshots (
    taken_at          TEXT PRIMARY KEY,
    vuln_series       INTEGER NOT NULL,
    node_series       INTEGER NOT NULL DEFAULT 0,
    violation_series  INTEGER NOT NULL
);

-- Aggregate counts per run (from the low-cardinality severity descriptor):
-- powers backlog-trend reports without a time-series database.
CREATE TABLE IF NOT EXISTS vuln_severity_counts (
    taken_at          TEXT NOT NULL,
    cluster           TEXT NOT NULL,
    namespace         TEXT NOT NULL,
    severity          TEXT NOT NULL,
    fixable           TEXT NOT NULL,
    platform_workload TEXT NOT NULL,
    findings          INTEGER NOT NULL,
    PRIMARY KEY (taken_at, cluster, namespace, severity, fixable, platform_workload)
);

-- ------------------------------------------------------------ report views

-- MTTR (median + p90, days) over vulns closed in the last 90 days.
-- Median = avg of the middle row(s); p90 = value at ceil(0.9 * n).
-- Excludes the bootstrap cohort (first_seen = first-ever collect): those
-- findings were already open when collection started, so their true age is
-- unknown - metrics carry no dates. MTTR covers only observed discoveries.
CREATE VIEW IF NOT EXISTS v_mttr AS
WITH closed AS (
    SELECT severity,
           julianday(closed_at) - julianday(first_seen) AS days
    FROM vuln_findings
    WHERE closed_at IS NOT NULL
      AND julianday(closed_at) > julianday('now') - 90
      AND first_seen > (SELECT min(taken_at) FROM snapshots)
), ranked AS (
    SELECT severity, days,
           row_number() OVER (PARTITION BY severity ORDER BY days) AS rn,
           count(*)     OVER (PARTITION BY severity)               AS cnt
    FROM closed
)
SELECT severity,
       max(cnt) AS closed,
       round(avg(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2) THEN days END), 1) AS median_days,
       round(max(CASE WHEN rn = (9 * cnt + 9) / 10 THEN days END), 1)              AS p90_days
FROM ranked
GROUP BY severity;

CREATE VIEW IF NOT EXISTS v_closed_weekly AS
SELECT strftime('%Y-W%W', closed_at) AS week,
       severity,
       count(*) AS closed
FROM vuln_findings
WHERE closed_at IS NOT NULL
GROUP BY 1, 2
ORDER BY 1 DESC, 2;

CREATE VIEW IF NOT EXISTS v_open_backlog AS
SELECT image_registry || '/' || image_remote || ':' || image_tag AS image,
       count(*)                                                  AS open_cves,
       sum(severity LIKE 'CRITICAL%')                            AS critical,
       sum(fixable = 'true')                                     AS fixable,
       substr(min(first_seen), 1, 10)                            AS oldest_since
FROM vuln_findings
WHERE closed_at IS NULL AND retired_at IS NULL
GROUP BY 1
ORDER BY critical DESC, fixable DESC;

CREATE VIEW IF NOT EXISTS v_reopened AS
SELECT cve,
       image_registry || '/' || image_remote || ':' || image_tag AS image,
       severity, reopen_count,
       substr(first_seen, 1, 10) AS first_seen,
       substr(last_seen, 1, 10)  AS last_seen
FROM vuln_findings
WHERE reopen_count > 0
ORDER BY reopen_count DESC, last_seen DESC;

-- % of fixable criticals closed within 30 days, per quarter (SLA style).
CREATE VIEW IF NOT EXISTS v_sla_critical_30d AS
SELECT strftime('%Y', closed_at) || '-Q' ||
           ((CAST(strftime('%m', closed_at) AS INTEGER) + 2) / 3) AS quarter,
       count(*) AS closed,
       round(100.0 * sum(julianday(closed_at) - julianday(first_seen) <= 30)
             / count(*), 1) AS pct_within_30d
FROM vuln_findings
WHERE closed_at IS NOT NULL AND severity LIKE 'CRITICAL%' AND fixable = 'true'
  AND first_seen > (SELECT min(taken_at) FROM snapshots)
GROUP BY 1
ORDER BY 1 DESC;

-- Violation resolution time (policy MTTR), resolved in last 90 days.
CREATE VIEW IF NOT EXISTS v_violation_mttr AS
WITH resolved AS (
    SELECT severity, stage,
           julianday(resolved_at) - julianday(first_seen) AS days
    FROM violation_findings
    WHERE resolved_at IS NOT NULL
      AND julianday(resolved_at) > julianday('now') - 90
      AND first_seen > (SELECT min(taken_at) FROM snapshots)
), ranked AS (
    SELECT severity, stage, days,
           row_number() OVER (PARTITION BY severity, stage ORDER BY days) AS rn,
           count(*)     OVER (PARTITION BY severity, stage)               AS cnt
    FROM resolved
)
SELECT severity, stage,
       max(cnt) AS resolved,
       round(avg(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2) THEN days END), 1) AS median_days
FROM ranked
GROUP BY severity, stage;

CREATE VIEW IF NOT EXISTS v_backlog_trend AS
SELECT substr(taken_at, 1, 10) AS day,
       severity,
       sum(CASE WHEN fixable = 'true' THEN findings ELSE 0 END)  AS fixable,
       sum(CASE WHEN fixable = 'false' THEN findings ELSE 0 END) AS not_fixable
FROM vuln_severity_counts
WHERE platform_workload = 'false'
GROUP BY 1, 2
ORDER BY 1 DESC, 2;

-- Image rollouts: every digest change per repo:tag, newest first.
CREATE VIEW IF NOT EXISTS v_image_changes AS
SELECT image_registry || '/' || image_remote || ':' || image_tag AS image,
       substr(image_id, 1, 19)   AS digest,
       substr(first_seen, 1, 16) AS first_seen,
       substr(coalesce(gone_at, 'current'), 1, 16) AS gone_at
FROM image_history
ORDER BY image, first_seen DESC;

-- Why CVEs closed: rebuilds vs feed/VEX changes vs tag replacement.
CREATE VIEW IF NOT EXISTS v_closed_reasons AS
SELECT substr(closed_at, 1, 10) AS day,
       closed_reason,
       count(*) AS closed
FROM vuln_findings
WHERE closed_at IS NOT NULL
GROUP BY 1, 2
ORDER BY 1 DESC, 2;

-- Component leverage: one upgrade closes how many findings across images?
CREATE VIEW IF NOT EXISTS v_component_leverage AS
SELECT component, component_version,
       count(DISTINCT cve)                          AS cves,
       count(DISTINCT image_remote)                 AS images,
       count(*)                                     AS findings,
       sum(severity LIKE 'CRITICAL%')               AS critical,
       sum(fixable = 'true')                        AS fixable
FROM component_vuln_findings
WHERE closed_at IS NULL AND retired_at IS NULL
GROUP BY 1, 2
ORDER BY critical DESC, findings DESC;
