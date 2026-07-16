#!/usr/bin/env bash
#
# rhacs-metrics-report.sh - reports over the RHACS metrics ledger built by
# rhacs-metrics-collect.sh (SQLite).
#
# Source this file from your shell:
#
#   source examples/rhacs-metrics-report.sh
#
# Optional:
#
#   export RHACS_METRICS_DB=path.db    # SQLite file (default: rhacs-metrics.db)
#
# Commands:
#
#   rhacs-report-mttr [DAYS]        median/p90 time-to-close by severity over
#                                   vulns closed in the last DAYS (default 90)
#   rhacs-report-closed [WEEKS]     closed vulns per week x severity (default 12)
#   rhacs-report-open               open backlog per image, worst first
#   rhacs-report-trend [DAYS]       open findings by severity over time (default 30)
#   rhacs-report-reopened           regressions: findings that came back
#   rhacs-report-sla                % of fixable criticals closed within 30 days
#   rhacs-report-violations [DAYS]  policy violation resolution times (default 90)
#   rhacs-report-images [DAYS]      image digest changes (rollouts), default 30
#   rhacs-report-closed-reasons     why CVEs closed: rebuild vs feed vs retag
#   rhacs-report-nodes              node CVE backlog per node + recent closures
#
# Dependencies: sqlite3

_roxr_sql() {
    sqlite3 -header -column "${RHACS_METRICS_DB:-rhacs-metrics.db}" "$1"
}

rhacs-report-mttr() {
    local days="${1:-90}"
    _roxr_sql "
        WITH closed AS (
            SELECT severity,
                   julianday(closed_at) - julianday(first_seen) AS days
            FROM vuln_findings
            WHERE closed_at IS NOT NULL
              AND julianday(closed_at) > julianday('now') - $days
              -- bootstrap cohort excluded: true age unknown (metrics-only)
              AND first_seen > (SELECT min(taken_at) FROM snapshots)
        ), ranked AS (
            SELECT severity, days,
                   row_number() OVER (PARTITION BY severity ORDER BY days) AS rn,
                   count(*)     OVER (PARTITION BY severity)               AS cnt
            FROM closed
        )
        SELECT severity,
               max(cnt) AS closed,
               round(avg(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2)
                              THEN days END), 1) AS median_days,
               round(max(CASE WHEN rn = (9 * cnt + 9) / 10
                              THEN days END), 1) AS p90_days
        FROM ranked
        GROUP BY severity
        ORDER BY CASE WHEN severity LIKE 'CRITICAL%' THEN 0
                      WHEN severity LIKE 'IMPORTANT%' THEN 1
                      WHEN severity LIKE 'MODERATE%' THEN 2 ELSE 3 END;"
}

rhacs-report-closed() {
    local weeks="${1:-12}"
    _roxr_sql "
        SELECT strftime('%Y-W%W', closed_at) AS week, severity, count(*) AS closed
        FROM vuln_findings
        WHERE closed_at IS NOT NULL
          AND julianday(closed_at) > julianday('now') - $weeks * 7
        GROUP BY 1, 2 ORDER BY 1 DESC, 2;"
}

rhacs-report-open() {
    _roxr_sql "SELECT * FROM v_open_backlog;"
}

rhacs-report-trend() {
    local days="${1:-30}"
    _roxr_sql "
        SELECT * FROM v_backlog_trend
        WHERE julianday(day) > julianday('now') - $days;"
}

rhacs-report-reopened() {
    _roxr_sql "SELECT * FROM v_reopened;"
}

rhacs-report-sla() {
    _roxr_sql "SELECT * FROM v_sla_critical_30d;"
}

rhacs-report-images() {
    local days="${1:-30}"
    _roxr_sql "
        SELECT * FROM v_image_changes
        WHERE julianday(first_seen) > julianday('now') - $days
           OR (gone_at != 'current' AND julianday(gone_at) > julianday('now') - $days);"
}

rhacs-report-closed-reasons() {
    _roxr_sql "SELECT * FROM v_closed_reasons;"
}

rhacs-report-nodes() {
    _roxr_sql "
        SELECT cluster, node,
               count(*)                       AS open_cves,
               sum(severity LIKE 'CRITICAL%') AS critical,
               sum(fixable = 'true')          AS fixable,
               sum(snoozed = 'true')          AS snoozed,
               substr(min(first_seen), 1, 10) AS oldest_since
        FROM node_vuln_findings
        WHERE closed_at IS NULL AND retired_at IS NULL
        GROUP BY 1, 2 ORDER BY critical DESC, fixable DESC;"
    echo
    _roxr_sql "
        SELECT substr(closed_at, 1, 10) AS day, count(*) AS closed
        FROM node_vuln_findings
        WHERE closed_at IS NOT NULL
        GROUP BY 1 ORDER BY 1 DESC LIMIT 14;"
}

rhacs-report-violations() {
    local days="${1:-90}"
    _roxr_sql "
        WITH resolved AS (
            SELECT severity, stage,
                   julianday(resolved_at) - julianday(first_seen) AS days
            FROM violation_findings
            WHERE resolved_at IS NOT NULL
              AND julianday(resolved_at) > julianday('now') - $days
              AND first_seen > (SELECT min(taken_at) FROM snapshots)
        ), ranked AS (
            SELECT severity, stage, days,
                   row_number() OVER (PARTITION BY severity, stage ORDER BY days) AS rn,
                   count(*)     OVER (PARTITION BY severity, stage)               AS cnt
            FROM resolved
        )
        SELECT severity, stage,
               max(cnt) AS resolved,
               round(avg(CASE WHEN rn IN ((cnt + 1) / 2, (cnt + 2) / 2)
                              THEN days END), 1) AS median_days
        FROM ranked
        GROUP BY severity, stage;"
    echo
    _roxr_sql "
        SELECT severity, count(*) AS open_now,
               substr(min(first_seen), 1, 10) AS oldest
        FROM violation_findings
        WHERE resolved_at IS NULL AND retired_at IS NULL
        GROUP BY 1 ORDER BY 1;"
}
