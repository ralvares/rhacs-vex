# VEX Triage Workflow

This document explains how `triage.py` and `triage_operators.py` work together to
determine whether a CVE finding from an RHACS image scan is a genuine vulnerability
or a false positive, using Red Hat's authoritative VEX (Vulnerability Exploitability
eXchange) data and the image SBOM.

---

## Overview

```
  RHACS scan
      │ CVE findings (component, version, CVE)
      ▼
  WorkloadContext         ◄── image reference + Docker labels + SBOM
      │ (scope: RHEL ver, product type, ns prefixes)
      ▼
  VEX fetch               ◄── https://security.access.redhat.com/data/csaf/v2/vex/
      │ CSAF 2.0 document (product_status, flags, threats)
      ▼
  audit_row_detailed()    ◄── per (component, version, CVE) row
      │
      ├─ ✅ FALSE POSITIVE  — vendor explicitly clears this product
      └─ ❌ POSITIVE        — affected, fix comparison done; no clearing found
```

---

## Data Sources

| Source | What it provides | Where cached |
|--------|-----------------|--------------|
| RHACS `/v1/images/scan` | CVE findings: component name, version, CVE ID, severity | in-memory |
| RHACS `/v1/images/sbom` | SPDX 2.3 SBOM: all packages + `GENERATED_FROM` relationships | `data/sbom/<image>.sbom` |
| Red Hat CSAF VEX | Authoritative product_status per CVE per product | `data/vex/<CVE>.json` |
| `data/ns_vex_prefixes.json` | Namespace → VEX product prefix map (built by `build_ns_map.py`) | `data/ns_vex_prefixes.json` |

---

## Step 1 — WorkloadContext

Before any VEX lookup, the image reference is parsed into a `WorkloadContext` that
tells the engine which VEX product IDs are in scope.

```python
@dataclass
class WorkloadContext:
    image_ref     : str          # registry.redhat.io/...@sha256:...
    rhel_ver      : str          # "8" or "9"
    workload_type : str          # "ubi" | "ocp" | "operator"
    ocp_ver       : str | None   # "4.21"  (ocp/operator only)
    image_ns      : str | None   # "3scale-amp2"
    image_name    : str | None   # "apicast-gateway-rhel8"
    display_name  : str          # human label for justification text
    extra_prefixes: list[str]    # catalog-derived VEX scope prefixes
    sbom_src_map  : dict         # binary RPM → source RPM  (see §3 below)
```

**Context derivation (no hardcoding):**

- `parse_image_ref(ref)` — derives type/ns/name purely from the image path
- `parse_context_from_labels(labels)` — refines from Docker `cpe` / `name` labels
- `extra_prefixes` — loaded from `data/ns_vex_prefixes.json`, which is built from
  the OLM operator catalogs by `build_ns_map.py`

---

## Step 2 — VEX Scope Filtering (`_pid_in_scope`)

For every product ID (PID) in a VEX document, the engine checks whether it applies
to this workload.  Rules — no hardcoded product names:

| Workload type | In-scope PIDs |
|---------------|---------------|
| `ubi` | RHEL base repos only (PIDs whose VEX name starts with *"Red Hat Enterprise Linux"*) |
| `ocp` | RHEL base repos + any PID whose parent product name contains *"OpenShift Container Platform"*, version-matched component-wise |
| `operator` | RHEL base repos + any PID whose ID contains a prefix from `ctx.extra_prefixes` |

---

## Step 3 — Binary → Source RPM Name Mapping

### The Problem

RHACS reports **binary RPM names** as installed in the container:

```
python3-urllib3    1.24.2-9.el8_10
openssl-libs       3.0.7-28.el9
libgcc             8.5.0-28.el8_10
```

Red Hat VEX product IDs use **source RPM names** (the package that was compiled):

```
red_hat_enterprise_linux_8:python-urllib3.src
red_hat_enterprise_linux_9:openssl
red_hat_enterprise_linux_8:gcc
```

One source RPM builds many binary packages:

```
source: util-linux  →  libsmartcols, libuuid, libmount, libblkid, ...
source: gcc         →  libgcc, libstdc++, libgomp, ...
source: python3     →  platform-python, python3-libs, ...
```

Without bridging this gap, every `python3-*` package would score `known_affected`
in RHACS but fall through to "not tracked in VEX → FALSE POSITIVE" in triage.

### The Fix — SBOM `GENERATED_FROM` Relationships

The SPDX 2.3 SBOM produced by RHACS encodes exactly this relationship:

```json
{
  "spdxElementId":    "SPDXRef-Package-78260",   ← python3-urllib3 (APPLICATION)
  "relatedSpdxElement": "SPDXRef-Package-78259", ← python-urllib3  (SOURCE)
  "relationshipType": "GENERATED_FROM"
}
```

At scan time, for every image, `triage.py` (and `triage_operators.py`) fetch the
SBOM and build `ctx.sbom_src_map`:

```python
# built automatically — zero hardcoding
{
  "python3-urllib3":  "python-urllib3",
  "python3-requests": "python-requests",
  "openssl-libs":     "openssl",
  "libgcc":           "gcc",
  "libsmartcols":     "util-linux",
  "platform-python":  "python3",
  ...  (one entry per binary package in the image)
}
```

`_resolve_comp(comp, ctx)` then returns **both** names for matching:

```
_resolve_comp("python3-urllib3", ctx)
    → {"python3-urllib3", "python-urllib3"}

VEX product_id: red_hat_enterprise_linux_8:python-urllib3.src
  parsed name:  "python-urllib3"
  in set?       ✅  → match found → correct verdict
```

### Sample mapping for `apicast-gateway-rhel8`

| Binary RPM (RHACS) | Source RPM (VEX) |
|--------------------|-----------------|
| `python3-urllib3` | `python-urllib3` |
| `python3-requests` | `python-requests` |
| `python3-chardet` | `python-chardet` |
| `python3-idna` | `python-idna` |
| `python3-six` | `python-six` |
| `python3-pysocks` | `python-pysocks` |
| `platform-python` | `python3` |
| `python3-libs` | `python3` |
| `openssl-libs` | `openssl` |
| `libgcc`, `libstdc++` | `gcc` |
| `libsmartcols`, `libuuid`, `libmount` | `util-linux` |
| `ncurses-libs`, `ncurses-base` | `ncurses` |
| `elfutils-libelf`, `elfutils-libs` | `elfutils` |
| `libnghttp2` | `nghttp2` |
| `systemd-libs`, `systemd-pam` | `systemd` |
| `dbus-libs`, `dbus-daemon`, `dbus-common` | `dbus` |
| *(139 total in this image — all from SBOM)* | |

---

## Step 4 — Module Stream Scope Guard

### The Problem

RHEL 8/9 support **module streams** — parallel versions of a package (e.g. `perl:5.26`
and `perl:5.32`).  VEX product IDs use a `::module:stream` suffix to scope an entry
to a specific stream:

```
red_hat_enterprise_linux_8:perl-Attribute-Handlers::perl:5.32  → known_not_affected
red_hat_enterprise_linux_8:perl                                 → known_affected
```

Without a guard, the engine would match the `::perl:5.32` (not_affected) entry
against a base system `perl 5.26.3-423.el8_10` and return FALSE POSITIVE —
even though the installed package is from the **different** base stream which IS
listed as `known_affected`.

### The Fix

RPMs installed from a module stream carry `+module+` in their release string:

```
# Module stream package
1.25.10-4.module+el8.5.0+11712+ea2d2be1   ← installed from python39:3.9 stream

# Base package
5.26.3-423.el8_10                          ← installed from base system (no +module+)
```

Two helpers enforce the guard in all PID loops:

```python
def _pid_module_stream(pid):
    """Return '::module:stream' token if present, else None."""
    return pid.split('::', 1)[1] if '::' in pid else None

def _version_is_module_stream(ver):
    """True if version-release contains '+module+' (RPM module stream package)."""
    return '+module+' in ver
```

Any PID qualified with `::` is **skipped** when the installed package has no
`+module+` in its version, and vice versa — a base-stream PID is never matched
against a module-stream installed package.

---

## Step 5 — `audit_row_detailed` Decision Tree

For each `(component, version, CVE)` row, after loading the VEX file:

```
1. Red Hat states NO product is affected (catch-all red_hat_products PID)?
   └─ ✅ FALSE POSITIVE

2. Non-RPM component (Go binary, npm, pip — no el8/el9 in version string)?
   ├─ Check scope-specific flags and product_status entries
   └─ Result based on what VEX says for this product family

3. RPM component — resolve names: {binary_name, source_name}
   │
   ├─ [not_affected_ids in scope, module-stream guard applies]
   │    pkg_name in resolved_names?
   │    └─ ✅ FALSE POSITIVE
   │
   ├─ [fixed PIDs in scope, module-stream guard applies]
   │    pkg_name in resolved_names + fix version exists?
   │    ├─ Same minor stream AND installed ≥ fix version → ✅ FALSE POSITIVE
   │    ├─ Same minor stream AND installed < fix version → ❌ POSITIVE (fix available)
   │    └─ Fix only in other minor streams              → ❌ POSITIVE (fix not in this stream)
   │
   ├─ [known_affected in scope, module-stream guard applies]
   │    pkg_name in resolved_names?
   │    └─ ❌ POSITIVE (with context: fix exists elsewhere, or no fix yet)
   │
   ├─ [under_investigation in scope]
   │    └─ ❌ POSITIVE (treat as vulnerable)
   │
   └─ [no in-scope entry — check other RHEL products for this comp]
        other_vuln only?    → ❌ POSITIVE
        other_safe only?    → ✅ FALSE POSITIVE
        nothing at all?     → ✅ FALSE POSITIVE (not tracked)
```

---

## Step 6 — SBOM Verification

After auditing, `_verify_sbom_against_df` cross-checks every component version in
the triage results against the SBOM package list.  This confirms that RHACS reported
the exact same versions that are actually present in the image.

Output example:
```
🔍 SBOM verified: 96/96 component versions confirmed in image
```

---

## Code Paths by Mode

| CLI mode | Entry point | SBOM fetched? | SBOM src map built? |
|----------|-------------|--------------|---------------------|
| `--image` (API) | inline in `main()` | ✅ yes | ✅ yes |
| `--namespace` (API) | `_fetch_and_audit()` | ✅ yes | ✅ yes |
| `--ocp` (API) | `_fetch_and_audit()` | ✅ yes | ✅ yes |
| `--scan` (CSV) | `_audit_and_display()` | ❌ no API | ⚠️ empty (name-exact only) |
| `triage_operators.py` | `_scan_and_audit_image()` | ✅ yes | ✅ yes |

---

## Data Flow Diagram

```
registry.redhat.io/<image>@sha256:<digest>
        │
        ├──► RHACS POST /v1/images/scan ──────► CVE findings (component, version, CVE)
        │                                              │
        └──► RHACS GET  /v1/images/sbom ──────► SPDX SBOM
                  │                                    │
                  │  GENERATED_FROM relationships       │
                  └──► sbom_src_map                     │
                       {binary → source}         audit_row_detailed()
                              │                        │
                              └──────────────► _resolve_comp()
                                                       │
                              Red Hat VEX ────► _pid_in_scope()
                  (security.access.redhat.com)         │  module-stream guard
                                                       │
                                               ✅ FALSE POSITIVE
                                               ❌ POSITIVE
```

---

## Key Invariants

- **No hardcoded package names** anywhere in the triage engine.  All mappings come
  from the SBOM (`GENERATED_FROM`), the VEX product tree (`_build_pid_name`), or
  the catalog-derived namespace map (`ns_vex_prefixes.json`).
- **No hardcoded VEX product IDs**.  RHEL base repo PIDs are identified by their
  VEX tree name starting with *"Red Hat Enterprise Linux"*.
- **Module stream isolation**.  `+module+` in a version string is the only signal
  used to decide whether a `::module:stream` PID applies to an installed package.
- **SBOM is the bridge**.  The SPDX SBOM is produced by the same scanner (RHACS)
  that generates the CVE findings, so binary→source mappings are always consistent
  with what is actually installed in the image.
