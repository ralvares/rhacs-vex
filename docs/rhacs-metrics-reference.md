# RHACS Custom Prometheus Metrics — Production Reference

What the RHACS `/metrics` endpoint offers, how to configure and consume it,
and what can be built on it. Verified against Central **4.11.1** (live
cluster + stackrox source at tag `4.11.1`). Intended as a working reference
for a production implementation.

---

## 1. Overview

RHACS Central can expose its security findings — image vulnerabilities, node
vulnerabilities, policy violations — as **customizable Prometheus metrics**.
You choose which dimensions (labels) each metric carries; Central aggregates
its current state into gauge series and serves them in Prometheus text
format. This turns RHACS data into something any observability stack can
consume: Prometheus, VictoriaMetrics, OpenShift monitoring, ACM
Observability, Grafana, or a custom collector.

Key property: the endpoint always reports **current state** (last gathering
run). It carries **no timestamps and no history** — trending and lifecycle
tracking are the consumer's job (see §8 and §9.6).

## 2. Endpoint and access

| | |
|---|---|
| URL | `GET https://<central>/metrics` |
| Port | main API port (**443**) — not the operational metrics port 9090 |
| Format | Prometheus text exposition |
| Auth | Bearer token, `Administration: READ` permission |
| Scoping | label values are filtered by the token's **access scope** |
| Compression | gzip supported |

The scoping property is a feature: a token scoped to a team's namespaces
yields only that team's series, so different Prometheus instances (or
tenants) can scrape with different tokens and each sees only its slice.

Recommended production setup: a dedicated machine-to-machine token (or API
token bound to a minimal role) with `Administration: READ` only, rotated on
the same schedule as other service credentials.

### Gathering model (important for consumers)

Metric values are recomputed by background gatherers, per group, every
`gatheringPeriodMinutes`. A scrape serves the **cached** registry and only
triggers a re-gather when the period has elapsed. Consequences:

- The **first scrape after enabling or changing configuration returns no
  custom series**. Data appears on subsequent scrapes once gathering
  completes. Consumers must tolerate an empty response without treating it
  as "zero findings".
- Data freshness = gathering period, regardless of scrape frequency.
- Scraping more often than the gathering period is cheap (cache reads) but
  yields no fresher data.

## 3. Configuration

Lives in Central's private config: `GET/PUT /v1/config` →
`privateConfig.metrics`, or portal → Platform Configuration → System
Configuration → Prometheus metrics.

```json
"metrics": {
  "imageVulnerabilities": {
    "gatheringPeriodMinutes": 60,
    "descriptors": {
      "severity": {
        "labels": ["Cluster","Namespace","Severity","IsFixable"],
        "includeFilters": {},
        "excludeFilters": { "Namespace": "kube-.*" }
      }
    }
  }
}
```

- **Groups** (4.11.1): `imageVulnerabilities`, `nodeVulnerabilities`,
  `policyViolations`. (`administrativeEvents` exists only in newer releases.)
- **`gatheringPeriodMinutes`**: 0 disables the group. 60 is a sensible
  production default; the data changes on scan cadence, not seconds.
- **Descriptors**: map of metric name → allowed label list. The metric's
  full name becomes `<group prefix>_<descriptor name>` (see §4).
- **`includeFilters` / `excludeFilters`**: per-label RE2 regex, full-match,
  applied at gathering time. Use them to drop platform noise or restrict to
  severities of interest *before* series are created.
- Invalid label names are rejected with an error message that lists the
  valid labels for the group — useful for discovering the label set of a
  new RHACS version.

### Change-management gotchas (verified behavior)

1. **A descriptor's label set cannot be altered.** The API rejects the PUT
   with `cannot alter metrics [...]`.
2. **Delete + recreate under the same name does not work** within one
   Central lifetime: validation passes, but the metric never serves again
   until Central restarts (the underlying Prometheus registry retains the
   old label schema). **Always introduce changed metrics under a new
   descriptor name**, and plan consumer-side renames accordingly.
3. After any config change, affected gatherers re-run only when their
   period elapses. For a faster rollout check: temporarily set the group's
   period low (e.g. 5), verify series, restore the production period.

### Rollout checklist

1. Create the scrape token (minimal role, `Administration: READ`).
2. PUT the metrics configuration; expect HTTP 200 and the config echoed.
3. Scrape once (empty, triggers gathering), scrape again after the period —
   verify expected series names and label sets.
4. Point the production scraper at the endpoint (§8).
5. Record the descriptor names and label sets in your runbook — renames
   require consumer changes (gotcha 1–2).

## 4. Metric groups and label catalog

Gauge value = **number of findings** matching the label combination. Fewer
labels → findings aggregate into larger counts; more labels → finer series.
All label values are strings (numeric-looking ones included).

A *finding* is, per group:

| Group | Metric name pattern | One finding = |
|---|---|---|
| `imageVulnerabilities` | `rox_central_image_vuln_<descriptor>` | deployment × image × component × CVE |
| `nodeVulnerabilities` | `rox_central_node_vuln_<descriptor>` | node × component × CVE |
| `policyViolations` | `rox_central_policy_violation_<descriptor>` (**singular** `violation`) | alert violation |

### 4.1 imageVulnerabilities — 19 labels

Example values are from a live 4.11.1 OpenShift cluster.

| Label | Meaning | Example values |
|---|---|---|
| `CVE` | CVE / advisory identifier | `CVE-2021-44228` |
| `CVSS` | CVSS score, 1 decimal, as string | `0.0`–`10.0` |
| `Cluster` | secured cluster name | `production` |
| `Namespace` | workload namespace | `payments` |
| `Deployment` | workload name | `visa-processor` |
| `Type` | workload kind | `Deployment`, `DaemonSet`, `StatefulSet`, `CronJob`, `Pod` |
| `IsActive` | workload currently active (not inactive/orphaned) | `true`/`false` |
| `IsPlatformWorkload` | matches platform-component rules (OpenShift/layered products) | `true`/`false` |
| `ImageID` | full image digest | `sha256:4124a1…` |
| `ImageRegistry` | registry host | `quay.io` |
| `ImageRemote` | repository path | `vuln/visa-processor` |
| `ImageTag` | tag; **empty for digest-only references** | `latest`, `v4.21`, `` |
| `Component` | package/library carrying the CVE | `org.apache.struts:struts2-core`, `golang.org/x/crypto`, `httpd` |
| `ComponentVersion` | installed (vulnerable) version | `2.5`, `v0.42.0` |
| `OperatingSystem` | image base OS | `rhel:9`, `debian:9`, `alpine:3.22` |
| `Severity` | vulnerability severity | `CRITICAL_VULNERABILITY_SEVERITY`, `IMPORTANT_…`, `MODERATE_…`, `LOW_…`, `UNKNOWN_…` |
| `IsFixable` | a fixed version exists | `true`/`false` |
| `EPSSProbability` | EPSS exploit probability, rounded to 1 decimal | `0.0`–`1.0` |
| `EPSSPercentile` | EPSS percentile, rounded to 1 decimal | `0.0`–`1.0` |

### 4.2 nodeVulnerabilities — 14 labels

| Label | Meaning | Example values |
|---|---|---|
| `Cluster` | secured cluster | `production` |
| `Node` | node name | `master-0`, `compute-1` |
| `Kernel` | kernel version | `5.14.0-570.118.1.el9_6.x86_64` |
| `OSImage` | node OS description | `Red Hat Enterprise Linux CoreOS 9.6…` |
| `OperatingSystem` | scanner OS identifier (may be empty on RHCOS) | |
| `Component` | host package | `glibc`, `crun`, `bind-libs` |
| `ComponentVersion` | package version | `2.34-168.el9_6.24` |
| `CVE` / `CVSS` / `Severity` / `IsFixable` | as in §4.1 | |
| `IsSnoozed` | node CVE snoozed in RHACS | `true`/`false` |
| `EPSSProbability` / `EPSSPercentile` | as in §4.1 | |

### 4.3 policyViolations — 16 labels

| Label | Meaning | Example values |
|---|---|---|
| `Cluster` / `Namespace` | where the alert fired | |
| `Deployment` | workload (deployment-entity alerts) | `visa-processor` |
| `Resource` | resource name (audit-log/resource alerts); empty otherwise | `my-secret` |
| `Entity` | alert entity kind | `DEPLOYMENT`, `IMAGE`, `RESOURCE` |
| `EntityName` | display name of the entity | |
| `Policy` | policy name | `Privileged Container`, `Log4Shell: …` |
| `Categories` | policy categories, comma-joined, sorted | `Privileges,Vulnerability Management` |
| `Severity` | policy severity | `CRITICAL_SEVERITY`, `HIGH_…`, `MEDIUM_…`, `LOW_…` |
| `Action` | enforcement taken | `UNSET_ENFORCEMENT`, enforcement enums |
| `Stage` | lifecycle stage | `DEPLOY`, `RUNTIME`, `BUILD` |
| `State` | alert state — **resolved alerts are exposed too** | `ACTIVE`, `RESOLVED` |
| `Type` | violation type | `GENERIC`, `K8S_EVENT`, `NETWORK_FLOW` |
| `IsDeploymentActive` | workload still running | `true`/`false` |
| `IsPlatformComponent` | platform-component flag | `true`/`false` |
| `Message` | violation message text — **avoid**: unbounded per-event values, one series per event | |

Notes with production value:

- `Stage=RUNTIME` + `Type=NETWORK_FLOW`/`K8S_EVENT` surfaces runtime
  activity (network-baseline deviations, exec-into-pod) — the only runtime
  signal available via metrics.
- `State=RESOLVED` means RHACS's own alert-resolution state is queryable —
  violation resolution does not have to be inferred.

## 5. Built-in metrics (always on, fixed 60-min period)

| Metric | Labels | Value semantics |
|---|---|---|
| `rox_central_health_cluster_info` | `Cluster`, `Type`, `Status`, `Upgradability` | 1 per cluster |
| `rox_central_cert_exp_hours` | `Component` ∈ `CENTRAL`, `CENTRAL_DB`, `SCANNER`, `SCANNER_V4` | **hours until certificate expiry** |
| `rox_central_cfg_total_policies` | `Enabled` | number of policies |

Mind the differing value semantics: `cert_exp_hours` is a duration, not a
count. Alert rule example: `rox_central_cert_exp_hours < 720` (30 days).

## 6. Cardinality and sizing

Series count = distinct combinations of the chosen labels. Real-world
reference points (small demo cluster, ~160 workloads, 30 image repos):

| Descriptor labels | Series |
|---|---|
| Namespace × Severity × IsFixable (aggregate) | ~440 |
| CVE × image identity | ~6,500 |
| CVE × Deployment | ~15,700 |
| all 19 labels (full detail) | ~24,600 (~14 MB per scrape) |

Guidance:

- **Dashboards / fleet rollups**: aggregate descriptors only (Severity,
  Cluster, Namespace, IsFixable, IsPlatformWorkload). Hundreds of series.
- **Detail consumers** (custom collectors, per-CVE analytics): full-label
  descriptors are viable — tens of thousands of series is trivial for any
  TSDB — but keep them out of fleet-federation pipelines (§8.3).
- `Message` is the only label that is genuinely dangerous (unbounded).
- High-churn labels (`ImageID`, `ImageTag`) create new series on every
  rollout; TSDBs index dead series, so churn matters more than live count
  for long retention.
- Use `excludeFilters` (e.g. `IsPlatformWorkload: "true"`, or
  `Namespace: "kube-.*|openshift-.*"`) to cut noise at the source.

## 7. Value semantics and enums

- Vulnerability severities: `CRITICAL|IMPORTANT|MODERATE|LOW|UNKNOWN` +
  `_VULNERABILITY_SEVERITY` suffix.
- Policy severities: `CRITICAL|HIGH|MEDIUM|LOW` + `_SEVERITY` suffix.
- Booleans are string `true`/`false`.
- `CVSS`, `EPSSProbability`, `EPSSPercentile` are strings rounded to one
  decimal — fine for banding/filtering, not for precise scoring.
- `IsFixable` reflects "a fix version exists"; the fix version itself is
  not exposed (§10).

## 8. Consumption patterns

### 8.1 Direct Prometheus / VictoriaMetrics scrape

```yaml
scrape_configs:
  - job_name: rhacs
    scheme: https
    metrics_path: /metrics
    scrape_interval: 2m
    authorization:
      credentials_file: /etc/prometheus/rhacs_token
    static_configs:
      - targets: ["central.example.com:443"]
    tls_config:
      ca_file: /etc/prometheus/rhacs_ca.pem
```

Keep `scrape_interval` ≤ 2 minutes even though data refreshes hourly:
Prometheus's 5-minute staleness window makes series flicker out of instant
queries at slower intervals. For MTTR-style trend analysis, retention must
exceed typical vulnerability lifetimes (months–years) — consider
VictoriaMetrics or Thanos for long retention.

### 8.2 OpenShift user-workload monitoring

The endpoint needs a Bearer token, so the operator's built-in
ServiceMonitor (which covers the operational port) does not apply. Create a
ServiceMonitor in the Central namespace with `authorization.credentials`
referencing a token Secret, targeting the Central service's https port,
path `/metrics`.

### 8.3 ACM Observability (fleet dashboards)

Managed-cluster Prometheus scrapes Central (8.2), ACM's metrics-collector
federates to hub Thanos via the `uwl_metrics_list` section of the
`observability-metrics-custom-allowlist` ConfigMap. **Allowlist only
aggregate descriptors** — per-CVE series multiplied by fleet size bloats
the hub with no dashboard value. Hub Grafana gets the `cluster` label
stamped automatically → fleet heatmaps for free.

### 8.4 Custom collector

Any HTTP client with the token can consume the full text format — the
endpoint is a complete current-state snapshot on every read, which enables
state-diffing approaches (§9.6).

## 9. Use cases

### 9.1 Live security-posture dashboards

```promql
# fixable criticals, application workloads only
sum(rox_central_image_vuln_severity{Severity="CRITICAL_VULNERABILITY_SEVERITY",
    IsFixable="true", IsPlatformWorkload="false"})

# violations by severity and namespace
sum by (Namespace, Severity)
    (rox_central_policy_violation_namespace_severity{State="ACTIVE"})
```

### 9.2 Burn-down / trend tracking

Scraped gauges become time series automatically:

```promql
sum by (Severity) (rox_central_image_vuln_severity{IsPlatformWorkload="false"})
# net weekly change
-delta(sum(rox_central_image_vuln_severity{IsFixable="true"})[7d:])
```

Note: `delta` gives **net** change (new − fixed), not gross closures.

### 9.3 Alerting

```yaml
- alert: NewCriticalFixableVulns
  expr: sum(rox_central_image_vuln_severity{Severity="CRITICAL_VULNERABILITY_SEVERITY",IsFixable="true"}) > 0
- alert: RHACSCertExpiringSoon
  expr: rox_central_cert_exp_hours < 720
- alert: RuntimeViolationActive
  expr: sum(rox_central_policy_violation_namespace_severity{State="ACTIVE",Severity="CRITICAL_SEVERITY"}) > 0
```

### 9.4 Risk prioritization

With `CVSS`, `EPSSPercentile`, `IsFixable` as labels, "patch first" lists
can be ranked by real-world exploitability instead of severity alone
(e.g. filter `EPSSPercentile` ≥ `0.9` and `IsFixable="true"`).

### 9.5 Team / tenant scoping

Issue tokens with different access scopes; each scrape sees only in-scope
series. One Central, per-team Prometheus/Grafana views, no extra config in
RHACS itself.

### 9.6 Historical records: closed vulnerabilities and MTTR

RHACS removes fixed vulnerabilities from its state and stores no resolution
timestamps — the metrics endpoint inherits that. History must be
**reconstructed by the consumer** from consecutive state snapshots:

- a series (identified by CVE + image/deployment identity) **appears** →
  discovery observed at that timestamp;
- it **disappears** while its image/deployment is still reported → closure
  observed (precision = collection cadence);
- disappearance together with its whole image/workload → decommissioned,
  not fixed — count separately;
- with `ImageID` in the labels, closure cause is attributable: same tag
  with a **new digest** = fixed by rebuild/rollout; same digest still
  running = scanner feed / VEX change, not remediation.

MTTR then = median(closure − discovery) over observed findings. Two rules
keep it honest: findings already present at the very first snapshot have
unknown true age (exclude them from MTTR — the cohort shrinks to nothing
over time), and findings that reappear after closure are regressions, not
new fast fixes. This works with any stateful consumer: a database fed by a
periodic scrape, or a long-retention TSDB queried for series lifetimes.

### 9.7 Correlation queries

Because vulnerability and violation metrics share `Cluster`, `Namespace`,
`Deployment` labels, consumers can join them: e.g. workloads that have
critical fixable CVEs **and** run privileged **and** show runtime
violations (`Stage=RUNTIME`) — a risk short-list no single RHACS view
provides directly.

## 10. Limitations — what `/metrics` does not provide

| Not available | Implication / workaround |
|---|---|
| Timestamps (discovery, scan, resolution) | reconstruct via snapshots (§9.6) |
| `fixedBy` (version that fixes a CVE) | only boolean `IsFixable`; fix versions require the API/reports |
| CVE metadata (description, link, CVSS vector) | join on `CVE` id against external data |
| Vulnerability exceptions / deferrals state | API only |
| Network graph, network/process baselines | only indirectly, via policies that alert on them |
| Violation event details | `Message` label exists but is unusable (§4.3) |
| Gross closure counts | gauges give net deltas; gross requires snapshot diffing (§9.6) |

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Scrape returns only built-in metrics | group disabled (`gatheringPeriodMinutes: 0` or `metrics: null`), or first scrape after config — retry after the period |
| Custom metric missing after a config change | label-set change under an existing name (§3 gotchas) — use a new descriptor name or restart Central |
| `cannot alter metrics [...]` on PUT | same — new descriptor name |
| Series flicker in Prometheus queries | scrape interval > 5-min staleness window — scrape ≤ 2m |
| Two scrapers see different data | tokens have different access scopes (by design) |
| Empty `ImageTag` label values | digest-referenced images — expected |
