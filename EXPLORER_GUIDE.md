# RHACS VEX Triage Explorer — User Guide

A browser-based search interface for querying triage results across all OCP operator and release
reports. Powered by [DuckDB-WASM](https://duckdb.org/) — runs entirely in the browser; no server
required once the parquet is loaded.

---

## Quick Start

```bash
# 1. Build / refresh the parquet (after adding new scan reports)
python3 build_parquet.py

# 2. Serve the UI
python3 -m http.server 8080

# 3. Open in browser
open http://localhost:8080
```

The parquet file (`data/ocp.parquet`) is auto-loaded on startup. You can also click
**Load Parquet** to pick a file manually.

---

## Search

The search box accepts **four types of input**:

| What you type | What it searches |
|---|---|
| `CVE-2025-68121` | CVE column only |
| `68121` | CVE column only (partial match) |
| `openshift-gitops` | Component, OCP component, image |
| `lasso` | Package / component name in all fields |
| `registry.redhat.io` | Image URL fragment |

Anything that looks like a CVE number (digits, optional year prefix) is searched against the CVE
column only for speed and precision. Everything else is a broad search across CVE, component, OCP
component, and image.

---

## Result Cards

After a search, four summary cards appear:

| Card | Meaning |
|---|---|
| **Total Findings** | All rows matching your query |
| **Unique Images** | Distinct container images affected |
| **Unique Packages** | Distinct package names affected |
| **Severity Mismatches** | Rows where VEX advisory severity ≠ RHACS scan severity |

---

## Filter Bar

Narrow results using the multi-select dropdowns:

| Filter | Description |
|---|---|
| **OCP Version** | e.g. `OCP 4.20`, `OCP 4.21` |
| **Component** | Operator or OCP component name |
| **Channel** | Operator channel (e.g. `stable`, `gitops-1.20`) |
| **Pkg Version** | Package version string |
| **VEX Severity** | Severity from Red Hat's VEX advisory |
| **RHACS Severity** | Severity as reported by the RHACS scan |
| **State** | `False Positive` / `Positive` / `In Review` |
| **Image** | Container image base URL (without digest) |
| **Mismatches only** | Toggle pill — show only rows where VEX ≠ RHACS severity |

Multiple filters can be active simultaneously. Click **Clear all** to reset everything.

---

## Severity Column

When there is **no mismatch**, the severity column shows a single badge:

```
MEDIUM
```

When the VEX advisory severity **differs** from what RHACS reported, both are shown with an arrow:

```
MEDIUM  →  CRITICAL  ⚠
```

- Left badge = VEX / Red Hat advisory rating
- Right badge = original RHACS scan rating
- ⚠ = hover tooltip confirms the discrepancy

This pattern matters most when investigating **False Positives rated Critical by RHACS** —
the VEX advisory may downgrade them to Moderate/Low because the vulnerable code path is
not present or not reachable in the Red Hat build.

---

## Example Searches

### By CVE

Search for a single CVE across all operators and OCP versions:

```
CVE-2025-68121
```
> Go `stdlib` — RHACS rates it **Critical**, Red Hat VEX rates it **Moderate** (False Positive).
> Good example to explore the mismatch toggle.

```
CVE-2025-59375
```
> `expat` — RHACS **Important**, VEX **Moderate** (False Positive). Appears in 237+ images.

```
CVE-2026-33747
```
> `github.com/moby/buildkit` — RHACS **Critical**, VEX **Moderate** (Positive — still needs a fix).

```
CVE-2026-1229
```
> `github.com/cloudflare/circl` — RHACS **Critical**, VEX **Moderate** (False Positive).

```
CVE-2024-40635
```
> `github.com/containerd/containerd` — RHACS **Important**, VEX **Moderate** (Positive).

```
CVE-2023-44487
```
> `golang.org/x/net` (HTTP/2 Rapid Reset) — RHACS **Moderate**, VEX **Important** (False Positive).

### By package / component

Search for all findings related to a package or operator, then use the filter bar to drill down:

```
glibc
```
> Highest-frequency mismatch package (~626 rows). Filter by **VEX Severity = Moderate** and
> **RHACS Severity = Important** to see the exact discrepancy pattern.

```
openssl
```
> `openssl-libs` and `openssl` — many rows rated differently between VEX and RHACS.

```
openshift-gitops
```
> All findings for the OpenShift GitOps operator across every channel and OCP version.
> Use the **Channel** dropdown to narrow to a specific release, e.g. `gitops-1.20`.

```
lasso
```
> Returns all images that contain the `lasso` package. Cross-check with the **Mismatches only**
> pill to find which images have the most alarming discrepancies.

```
expat
```
> `expat` library — 237 images affected. RHACS often rates it Important while VEX says Moderate.

### Finding Critical mismatches (most actionable)

1. Search for a broad term like `stdlib` or `glibc`
2. Click **Mismatches only**
3. Select **RHACS Severity = Critical** from the dropdown
4. Review the **State** column — `False Positive` rows mean Red Hat has confirmed the
   risk is lower than RHACS suggests; `Positive` rows need immediate attention.

---

## Understanding Severity Mismatches

| Pattern | Interpretation |
|---|---|
| VEX = Moderate, RHACS = Critical | RHACS uses NVD/upstream severity; Red Hat's analysis rates it lower for their builds. Usually a False Positive. |
| VEX = Moderate, RHACS = Important | Same as above, one tier lower. Very common with Go stdlib / net packages. |
| VEX = Important, RHACS = Moderate | Rare — Red Hat rates it MORE severely than the upstream reporter. Worth investigating. |
| VEX = Low, RHACS = Moderate | RHACS may be using an older database entry. VEX is authoritative for RHEL/OCP. |
| VEX = UNKNOWN | VEX file exists but has no severity field; RHACS severity is the only signal. |

---

## Workflow: Triaging a Positive with Mismatched Severity

1. **Search** the CVE
2. **Check State** — is it already marked False Positive?
   - Yes → RHACS is scanning but Red Hat has confirmed it's not applicable. Safe to suppress.
   - No (Positive) → Check if **RHACS severity is higher** than VEX — this indicates RHACS is using
     upstream NVD data, which may not reflect the backported Red Hat fix status.
3. **Check Justification** — the text explains the exact reason (version fixed, code not present, etc.)
4. **Filter by OCP Version** to see if a newer OCP release has already addressed it.

---

## Data Coverage

| OCP Release | Report files |
|---|---|
| OCP 4.20 | `data/reports/ocp-4.20.x.csv` (core) + `data/reports/ocp-4.20/*.csv` (operators) |
| OCP 4.21 | `data/reports/ocp-4.21.x.csv` (core) + `data/reports/ocp-4.21/*.csv` (operators) |

All data is combined into `data/ocp.parquet`. Total: ~958 CSV files, ~3.1M rows.

---

## Regenerating the Parquet

Whenever new triage runs complete or existing CSVs are updated:

```bash
python3 build_parquet.py
```

Then reload the page — the browser will re-fetch `data/ocp.parquet` automatically.
