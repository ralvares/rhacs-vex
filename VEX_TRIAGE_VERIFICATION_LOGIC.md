> **Canonical reference:** For the full end-to-end technical explainer (all triage logic,
> verification, and architecture), see
> [VEX_TRIAGE_EXPLAINER.md](VEX_TRIAGE_EXPLAINER.md).
> This document is a concise verification-focused companion covering the same integrity
> checks from a presentation/audit perspective.

This document provides a technical breakdown of the automated security checks performed by the `triage.py` engine. It is designed to be used as a technical reference or as the basis for a security architecture presentation.

# **Title:** RHACS VEX Triage: Technical Integrity & Verification Framework

---

## **1. Overview**
The primary goal of this framework is to automate the decision-making process for Vulnerability Management. It determines if a CVE finding reported by a scanner (RHACS) is a **Genuine Positive** (Action Required) or a **False Positive** (No Risk).

The system achieves this by cross-referencing three distinct data layers:
1.  **Scanner Findings:** What the tool *thinks* is in the container.
2.  **Red Hat VEX (CSAF):** What the Vendor *authoritatively states* about the vulnerability.
3.  **SPDX SBOM:** The *physical proof* of package lineage and versioning within the image.

---

## **2. The Translation Layer: Binary-to-Source Mapping**
### **The Problem**
Scanners report **Binary RPMs** (e.g., `python3-urllib3`). However, security advisories are often published against the **Source RPM** (e.g., `python-urllib3`). Without a translation layer, automation fails because names do not match.

### **The Check**
The script parses the **SPDX SBOM** specifically looking for the `GENERATED_FROM` relationship.
* **Logic:** If `Package-A` (Binary) is `GENERATED_FROM` `Package-B` (Source), the triage engine automatically queries the VEX database for both names.
* **Outcome:** This ensures that vulnerabilities tracked under the "Source" name are correctly applied to the "Binary" package installed in the image.

---

## **3. The Triage Layer: Stream-Aware Auditing**
Red Hat Enterprise Linux (RHEL) uses "Backporting," meaning they fix security bugs in older versions of software without changing the major version number. A simple "is version A higher than version B" check is insufficient.

### **Minor Stream Isolation (`elN_M`)**
* **The Check:** The script uses `_detect_rhel_minor` to extract stream markers (e.g., `.el8_10` or `.el9_4`).
* **Logic:** It ensures that an installed package in the RHEL 9.2 stream is only compared against fixes released for the 9.2 stream. 
* **Outcome:** This prevents "False Negatives" where a fix in a newer minor release (9.4) is incorrectly assumed to have fixed an older release (9.2).

### **Module Stream Guarding**
* **The Check:** The script identifies if a package was installed via a "Module Stream" by looking for the `+module+` string in the version release.
* **Logic:** It matches these packages against VEX Product IDs containing the `::module:stream` suffix.
* **Outcome:** This ensures that "Base" system packages are never cleared by security advisories meant only for "Modular" versions of the same software.

---

## **4. The Non-RPM Logic (Go, npm, Python)**
For non-RPM components, version strings are often inconsistent and difficult to compare mathematically.

### **Contextual Scoping**
* **The Check:** Instead of comparing version numbers, the script checks for **Product ID (PID) Membership**.
* **Logic — three tiers, most specific first:**
    1. **OCI purl / SHA-exact match:** The engine builds the image's own OCI purl (`pkg:oci/{name}?repository_url=…`) from the image reference or `name` label and matches it exactly against the purls in the VEX product tree. Entries whose PID carries the scanned image's **exact SHA256 digest** are an assessment of *this build* and **override all generic entries** — e.g. a generic `known_affected` plus an our-digest `known_not_affected` means our build already contains the fix → **FALSE POSITIVE**. This digest override runs engine-wide **before the RPM/non-RPM branch**: a VEX statement about our exact build settles the verdict for *every* component in the image, RPMs included (affected wins over cleared when both digest entries exist).
    2. **Image-level (name normalization):** For PIDs without purls, the workload identity is matched by normalized image name (`openshift4/ose-etcd-rhel9` → `etcd`), including the `rhcos` ↔ `rhel-coreos` alias for the OCP base OS.
    3. **Generic product-level:** For non-SHA PIDs, the engine checks `product_status`:
        - `known_not_affected` → **FALSE POSITIVE** (vendor explicitly clears this product)
        - `fixed` → **POSITIVE** (a fix exists, but the installed version cannot be verified as patched — conservative to avoid silent false negatives)
        - `known_affected` / `under_investigation` → **POSITIVE**
* **Scope resolution:** In-scope products are determined structurally — RHEL base repos from VEX product names; OCP by product-name version matching **and** by prefix-matching the image's `cpe` label against VEX product-tree CPEs; operators via the catalog map plus a namespace→product map derived from OCI purls in the VEX file itself.
* **Outcome:** Purl and SHA matching provide build-level precision for bundled binaries.  Generic product-level matching is conservative — it never marks a finding as FALSE POSITIVE unless the vendor explicitly states "not affected."

---

## **5. The Integrity Guard: SBOM Consistency Check**
The final step is a "Sanity Check" to ensure the data provided by the scanner hasn't "drifted" from the reality of the image.

### **The Check: `_verify_sbom_against_df`**
* **Logic:** Every component version used in the final triage report is cross-referenced against the actual package list inside the SBOM.
* **Verification points:**
    1.  Does the package name exist in the SBOM?
    2.  Does the version string (after stripping the RPM epoch) match exactly?
* **Outcome:** If a mismatch is found, the tool issues a warning. This prevents the security team from signing off on a triage report based on stale or incorrect scanner data.

---

## **6. Summary of Verdicts**

| Verdict | Logic Applied |
| :--- | :--- |
| **✅ FALSE POSITIVE** | Vendor states the code is not present/executable (`known_not_affected`), OR the RPM version installed is ≥ the fix version for that specific RHEL minor stream (with at least one successful version comparison). |
| **❌ POSITIVE** | The version installed is older than the fix version, OR the vendor has marked the product as `known_affected` or `under_investigation`, OR a fix exists but the installed version cannot be verified (non-RPM `fixed` status). |
| **⚠️ MISMATCH** | The triage results do not align with the SBOM package list. Manual intervention is required to verify image contents. |

---

## **7. Reliability**

The engine is designed for safe concurrent operation and conservative defaults:

* **Atomic file I/O:** All cached files (VEX, scans, SBOMs) use atomic write-then-rename to prevent data corruption during parallel scans.
* **Conservative on ambiguity:** When version comparison fails (parse errors), the engine does NOT default to FALSE POSITIVE — at least one successful comparison is required.  Non-RPM `fixed` entries are treated as POSITIVE unless the exact image build is confirmed.
* **Corrupt file recovery:** Corrupt VEX JSON files are logged, deleted, and re-downloaded on the next run rather than being silently cached as "missing."
* **Explicit validation:** `--ocp` and `--namespace` modes fail fast with a clear error if `ROX_ENDPOINT` / `ROX_API_TOKEN` are not set, instead of silently falling through to CSV mode.
* **Vendor severity, most specific first:** Severity is resolved from VEX per-product threat ratings through a priority chain (OCI purl match → image-level PID → component-name PID → in-scope affected/fixed PID → document aggregate → generic threat → CVSS → scanner severity), so the reported rating reflects Red Hat's assessment for *this* product, not a generic CVSS score. Findings where the scanner and VEX disagree are flagged.
* **Regression baseline:** `check_baseline.py` replays a pinned set of real triage cases (errata-policy OCP versions, Fast Datapath scoping, minor-stream RPMs, a full `ose-cli` image scan) against `data/baseline.json` and exits non-zero if any verdict flips from FALSE POSITIVE to POSITIVE — run it after changing triage logic.

## **8. Conclusion**
By combining **lineage tracking** (SBOM), **minor stream isolation** (RPM math), and **vendor authority** (VEX), this script moves security operations from "Best Effort" guesses to **Provable Integrity**. Every decision made by the script is backed by a specific relationship or version comparison that is 100% auditable.